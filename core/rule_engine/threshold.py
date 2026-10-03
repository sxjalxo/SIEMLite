#!/usr/bin/env python3
"""
Threshold Windows
=================
One sliding window per group_by key. Insert, evict what is older than the
timeframe, fire when the window is full, then CLEAR the key.

Clearing is the whole design. A sliding window that keeps firing emits one
alert per event for as long as the burst continues, which buries the signal it
found. Re-arming means one alert per burst.

Out-of-order contract
---------------------
The window always holds only the events within `timeframe` of the NEWEST
timestamp seen for that key, kept sorted by timestamp. So an event that arrives
older than one already in the window:

  - inside the timeframe of the newest: it is inserted in timestamp order and
    counts toward the threshold; fired payloads come back oldest first.
  - outside it: it is evicted on arrival, never counts, and never fires.

It is never appended at the tail. Eviction pops from the left, so an unsorted
window would leave a stale event sitting behind newer ones, still counted: four
events in five minutes plus one from ten minutes earlier would alert as "five
in five minutes". Dropping a late in-window event instead would undercount a
real burst. Batch detection feeds timestamp order, but a run over several
channels can interleave them, so both cases are reachable.

Costs, accepted: the clock is the newest timestamp still in the window, so
firing (which empties the window) resets it. A late event from the burst that
just fired therefore starts a fresh window and can count toward the next burst.
Insertion scans from the tail, O(1) for in-order input and bounded by
count_gte for a late one.

ponytail: in-memory state, so a daemon restart loses partial windows. Spec
section 17 accepts that; persist to the store only if it proves to matter.
ponytail: one entry per distinct key ever seen, never freed. Sweep idle keys
if group_by cardinality (e.g. spraying source IPs) ever makes that matter.
"""

from collections import defaultdict, deque
from datetime import timedelta


class ThresholdTracker:
    def __init__(self, timeframe, count_gte):
        if timeframe <= timedelta(0):
            raise ValueError("timeframe must be positive")
        if count_gte < 1:
            raise ValueError("count_gte must be at least 1")
        self._timeframe = timeframe
        self._count = count_gte
        self._windows = defaultdict(deque)

    def add(self, key, timestamp, payload):
        window = self._windows[key]
        i = len(window)
        while i and window[i - 1][0] > timestamp:
            i -= 1
        window.insert(i, (timestamp, payload))
        newest = window[-1][0]
        while newest - window[0][0] > self._timeframe:
            window.popleft()
        if len(window) >= self._count:
            fired = tuple(p for _, p in window)
            window.clear()
            return fired
        return None

    def pending(self, key):
        return len(self._windows.get(key, ()))
