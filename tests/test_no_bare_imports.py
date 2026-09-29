"""Test that no Python code uses bare local module imports.

Bare local imports (e.g. `from report import ...` instead of
`from core.report import ...`) are forbidden because they only work
if the module is on sys.path, not when imported as a package.

This test derives packages from the filesystem: directories with __init__.py
plus root-level .py files. It walks all .py files, parses them with ast,
and asserts that no Import or ImportFrom node at any depth imports a bare
local module name.

Uses ast to ignore docstrings and comments automatically.
Allows relative imports (from . import x, from .. import y).
"""

import ast
import unittest
from pathlib import Path


def get_packages():
    """Derive packages from filesystem: directories with __init__.py + root .py files.

    Excludes __pycache__ and tests/.
    """
    repo_root = Path(__file__).parent.parent
    packages = []

    # Directories with __init__.py
    for item in repo_root.iterdir():
        if item.is_dir() and item.name not in ("__pycache__", "tests"):
            if (item / "__init__.py").exists():
                packages.append(item)

    # Root-level .py files
    for py_file in repo_root.glob("*.py"):
        packages.append(py_file)

    return packages


def py_files(packages):
    """Yield all .py files from packages."""
    for package in packages:
        if package.is_file():
            yield package
        else:
            for py_file in package.rglob("*.py"):
                if "__pycache__" not in py_file.parts:
                    yield py_file


class TestNoBareImports(unittest.TestCase):
    def test_no_bare_local_imports(self):
        """Assert no code uses bare local module names."""
        packages = get_packages()

        # Derive forbidden names from filesystem
        forbidden = {py_file.stem for py_file in py_files(packages) if py_file.name != "__init__.py"}

        violations = []
        files_scanned = 0

        for py_file in py_files(packages):
            files_scanned += 1
            # Parse file; SyntaxError is caught and recorded as violation
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            except SyntaxError as e:
                violations.append(f"{py_file}: SyntaxError at line {e.lineno}: {e.msg}")
                continue

            # Walk AST for all Import and ImportFrom nodes at any depth
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    # import x or import x.y.z
                    for alias in node.names:
                        bare_name = alias.name.split(".")[0]
                        if bare_name in forbidden:
                            violations.append(f"{py_file}: line {node.lineno}: bare import of '{bare_name}'")

                elif isinstance(node, ast.ImportFrom):
                    # from x import y or from x.y import z; relative imports (level > 0) are OK
                    if node.level == 0 and node.module:
                        bare_name = node.module.split(".")[0]
                        if bare_name in forbidden:
                            violations.append(f"{py_file}: line {node.lineno}: bare import of '{bare_name}'")

        self.assertTrue(files_scanned, "scanned no Python files")
        self.assertEqual([], violations, "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
