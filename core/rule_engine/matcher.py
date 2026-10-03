#!/usr/bin/env python3
"""
Rule Matcher
============
Does one event satisfy one selection? Everything else in the engine is
plumbing around this question.

Deliberate choices:

Strings compare case-insensitively, because Windows is case-insensitive about
usernames, paths and process names, and a rule that misses `Administrator`
because it was written `administrator` looks like a detection and is not one.
Both sides go through str(), so `event_id: '4625'` matches event_id=4625: YAML
quoting is an authoring accident, not a semantic choice.

A field name outside the normalized schema RAISES. Treating it as "no match"
turns a typo into a silently dead rule. The same goes for an unknown modifier,
an empty selection or an empty substring (each would match everything), a
key with no value, and a bad hour or regex. Every field of a selection is
checked even after one fails to match, so a typo raises whatever the event.

A range whose start is after its end wraps midnight: `22..5` is the night
shift. The alternative is the empty set, which would silently disable the rule.

The `condition` expression is parsed, never eval()'d: rule files get shared.
"""

import operator
import re
from datetime import datetime

from ingestion.normalizer import EVENT_FIELDS

# A parenthesis or a chain of `and` this long is a hostile or broken rule, and
# the recursive parser and evaluator would hit the recursion limit on it.
_MAX_TOKENS = 200

_TOKEN = re.compile(r"\(|\)|\b(?:and|or|not)\b|[A-Za-z_][A-Za-z0-9_]*")


def _text(value):
    """Comparable lower-cased text for any field value; None never reaches .lower()."""
    return "" if value is None else str(value).lower()


def _number(value):
    """float(value), or None when the value is not numeric."""
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _short(value, limit=40):
    """repr(value), cut so a hostile 5000-character value stays out of messages."""
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "...'"


def _regex(field, pattern):
    # RecursionError: deeply nested pattern. OverflowError: absurd repeat count.
    try:
        return re.search(str(pattern), _text(field), re.IGNORECASE) is not None
    except (re.error, RecursionError, OverflowError) as exc:
        raise ValueError("invalid regex {}: {}".format(_short(pattern), exc))


def _numeric(compare):
    """A field that is not a number never matches; a rule value that is not one raises."""
    def apply(field, want):
        limit, actual = _number(want), _number(field)
        if limit is None:
            raise ValueError("{} is not a usable number".format(_short(want)))
        return actual is not None and compare(actual, limit)
    return apply


def _equals(field, want):
    return _text(field) == _text(want)


# Per-value comparisons; a list of wanted values is OR-ed over these.
_COMPARE = {
    "in": _equals,
    "contains": lambda field, want: _text(want) in _text(field),
    "startswith": lambda field, want: _text(field).startswith(_text(want)),
    "endswith": lambda field, want: _text(field).endswith(_text(want)),
    "re": _regex,
    "gt": _numeric(operator.gt),
    "lt": _numeric(operator.lt),
    "gte": _numeric(operator.ge),
    "lte": _numeric(operator.le),
}



def parse_field_spec(spec):
    """'status|not|contains' -> ('status', ('not', 'contains')).

    Modifier names are not checked here: Task 3 reports them with a file and
    key, and _hit raising on an unknown one is the backstop.
    """
    name, *modifiers = (part.strip() for part in str(spec).split("|"))
    if not name:
        raise ValueError("field spec {!r} has no field name".format(spec))
    return name, tuple(modifiers)


def _hour_range(entry):
    """7 or '7..19' -> (7, 19)."""
    low, sep, high = str(entry).partition("..")
    try:
        low, high = int(low), int(high if sep else low)
    except ValueError:
        raise ValueError("bad hour {!r}: want 7 or 7..19".format(entry))
    if not (0 <= low <= 23 and 0 <= high <= 23):
        raise ValueError("bad hour {!r}: hours run 0 to 23".format(entry))
    return low, high


def _hour_in(timestamp, ranges):
    if not isinstance(timestamp, datetime):
        raise ValueError("hour_in and hour_not_in need a timestamp field")
    hour = timestamp.hour
    # A list, not a generator: see _hit. A bad range after a matching one must raise.
    return any([
        low <= hour <= high if low <= high else hour >= low or hour <= high
        for low, high in map(_hour_range, ranges)
    ])


# Hour modifiers read the whole wanted list as hour ranges, so they sit apart.
_HOUR = {
    "hour_in": _hour_in,
    "hour_not_in": lambda timestamp, ranges: not _hour_in(timestamp, ranges),
}

# `not` is not an operator, it flips one; match_selection handles it by name.
MODIFIERS = frozenset(_COMPARE) | frozenset(_HOUR) | {"not"}

# An empty string is a substring or prefix of everything: match-all, like {}.
_NEEDS_TEXT = ("contains", "startswith", "endswith", "re")


def _hit(value, op, wanted):
    """Whether `value` satisfies `op` against ANY of the wanted values."""
    if op in _HOUR:
        return _HOUR[op](value, wanted)
    if op not in _COMPARE:
        raise ValueError("unknown modifier {!r}".format(op))
    if op in _NEEDS_TEXT and "" in wanted:
        raise ValueError("{} with an empty string matches every event".format(op))
    # A list, not a generator: any() would stop at the first match and never
    # evaluate (so never reject) a bad value after it.
    return any([_COMPARE[op](value, want) for want in wanted])


def _field_matches(event, spec, value):
    field, modifiers = parse_field_spec(spec)
    if field not in EVENT_FIELDS:
        raise ValueError("{!r} is not an event field".format(field))
    wanted = value if isinstance(value, list) else [value]
    if not wanted or None in wanted:
        raise ValueError("{!r} has no value to match".format(spec))
    ops = [m for m in modifiers if m != "not"]
    if len(ops) > 1:
        raise ValueError("{!r} has more than one operator".format(spec))
    # `not` negates the whole OR, so not|contains: [a, b] means neither.
    negated = modifiers.count("not") % 2 == 1
    try:
        hit = _hit(getattr(event, field), ops[0] if ops else "in", wanted)
    except ValueError as exc:
        raise ValueError("{}: {}".format(spec, exc))
    return hit != negated


def match_selection(event, selection):
    """AND over the selection's field specs.

    The list is built before all() so every spec is checked even after one
    fails to match: a typo in the second key must raise for every event, not
    only for the events that matched the first.
    """
    if not isinstance(selection, dict) or not selection:
        raise ValueError("a selection needs at least one field")
    return all([_field_matches(event, spec, value)
                for spec, value in selection.items()])


def _tokenize(text, selection_names):
    """Tokens, or ValueError naming the first thing that is not one."""
    pos, tokens = 0, []
    for match in _TOKEN.finditer(text):
        if text[pos:match.start()].strip():
            raise ValueError("condition: unexpected {!r}".format(
                text[pos:match.start()].strip()))
        token = match.group(0)
        if token not in ("(", ")", "and", "or", "not") and token not in selection_names:
            raise ValueError(
                "condition names {!r}, which is not a selection in this rule "
                "(have: {})".format(token, ", ".join(sorted(selection_names))))
        tokens.append(token)
        pos = match.end()
    if text[pos:].strip():
        raise ValueError("condition: unexpected {!r}".format(text[pos:].strip()))
    if not tokens:
        raise ValueError("condition is empty")
    if len(tokens) > _MAX_TOKENS:
        raise ValueError("condition has {} tokens, the limit is {}".format(
            len(tokens), _MAX_TOKENS))
    return tokens


class _Parser:
    """Recursive descent: or binds loosest, then and, then not and parentheses."""

    def __init__(self, tokens):
        self.tokens, self.pos = tokens, 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        token = self.peek()
        self.pos += 1
        return token

    def chain(self, op, operand):
        node = operand()
        while self.peek() == op:
            self.take()
            node = (op, node, operand())
        return node

    def or_expr(self):
        return self.chain("or", self.and_expr)

    def and_expr(self):
        return self.chain("and", self.not_expr)

    def not_expr(self):
        if self.peek() == "not":
            self.take()
            return ("not", self.not_expr())
        return self.primary()

    def primary(self):
        token = self.take()
        if token == "(":
            node = self.or_expr()
            closer = self.take()
            if closer != ")":
                raise ValueError("condition: expected ')' but found {}".format(
                    "the end" if closer is None else repr(closer)))
            return node
        if token is None or token in (")", "and", "or"):
            raise ValueError(
                "condition: expected a selection name or '(' but found {}".format(
                    "the end" if token is None else repr(token)))
        return ("name", token)


def _walk(node, results):
    kind = node[0]
    if kind == "name":
        return results[node[1]]
    if kind == "not":
        return not _walk(node[1], results)
    # Both sides always evaluate: a missing result must raise every time,
    # not only when short-circuiting happens to reach it.
    left, right = _walk(node[1], results), _walk(node[2], results)
    return (left and right) if kind == "and" else (left or right)


class Condition:
    """A parsed condition. A KeyError from evaluate() means the engine forgot a
    selection; it is not defaulted to False, which would be a silent dead rule."""

    def __init__(self, tree):
        self._tree = tree

    def evaluate(self, results):
        return _walk(self._tree, results)


def parse_condition(text, selection_names):
    """Parse `sel and not filter` style text; ValueError names the bad token."""
    parser = _Parser(_tokenize(text, selection_names))
    tree = parser.or_expr()
    if parser.peek() is not None:
        raise ValueError("condition: unexpected {!r} after a complete expression".format(
            parser.peek()))
    return Condition(tree)


def match_event(event, selections, condition):
    """Evaluate every selection, then the condition over the results."""
    return condition.evaluate(
        {name: match_selection(event, sel) for name, sel in selections.items()})
