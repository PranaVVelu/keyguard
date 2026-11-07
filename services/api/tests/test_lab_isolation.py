"""D-005 / threat T13: deliberately vulnerable code must be unreachable from the hardened authorization path.

Builds a static import graph of app/ with the AST module and checks:
  1. The transitive imports of the hardened path (app.security.*, app.routes.auth, app.routes.keys,
     app.routes.labs) never include app.lab.
  2. Only app.routes.lab may import app.lab at all, and only via app.lab.scenarios (not the vulnerable package).
  3. The vulnerable package can't reach the database layer (no sqlalchemy, app.db or app.models imports).
"""

from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"


def _module_name(path: Path) -> str:
    rel = path.relative_to(APP.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):  # includes imports nested inside functions
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
            found.update(f"{node.module}.{a.name}" for a in node.names)
    return found


GRAPH = {_module_name(p): _imports(p) for p in APP.rglob("*.py")}


def _closure(start: str) -> set[str]:
    seen, stack = set(), [start]
    while stack:
        mod = stack.pop()
        if mod in seen:
            continue
        seen.add(mod)
        for imp in GRAPH.get(mod, ()):
            # Resolve "pkg.name" imports to the module if it exists, else the package.
            target = imp if imp in GRAPH else imp.rsplit(".", 1)[0]
            if target in GRAPH:
                stack.append(target)
    return seen


HARDENED_ROOTS = [m for m in GRAPH if m.startswith("app.security")] + ["app.routes.auth", "app.routes.keys", "app.routes.labs"]


def test_graph_sanity():
    assert "app.security.authenticate" in GRAPH
    assert "app.lab.vulnerable.verifier" in GRAPH
    # The checker must actually see the scenario route reaching the vulnerable code, or it proves nothing.
    assert "app.lab.vulnerable.verifier" in _closure("app.routes.lab")


def test_hardened_path_never_reaches_app_lab():
    for root in HARDENED_ROOTS:
        leaked = sorted(m for m in _closure(root) if m == "app.lab" or m.startswith("app.lab."))
        assert not leaked, f"{root} transitively imports {leaked}"


def test_only_the_lab_route_imports_app_lab_and_never_the_vulnerable_package_directly():
    for mod, imps in GRAPH.items():
        if mod.startswith("app.lab"):
            continue
        lab_imports = {i for i in imps if i == "app.lab" or i.startswith("app.lab.")}
        if mod == "app.routes.lab":
            assert all(i.startswith("app.lab.scenarios") for i in lab_imports), lab_imports
        elif mod != "app.main":
            assert not lab_imports, f"{mod} imports {lab_imports}"
    assert not {i for i in GRAPH["app.main"] if i.startswith("app.lab")}


def test_vulnerable_package_cannot_reach_the_database():
    for mod, imps in GRAPH.items():
        if mod.startswith("app.lab.vulnerable"):
            bad = {i for i in imps if i.split(".")[0] == "sqlalchemy" or i.startswith(("app.db", "app.models"))}
            assert not bad, f"{mod} imports {bad}"
