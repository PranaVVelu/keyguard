"""DELIBERATELY VULNERABLE CODE, for the Attack Lab comparison only (D-005).

Nothing in app.security or app.routes.auth may import this package; tests/test_lab_isolation.py enforces it.
It holds only in-memory state and never touches the real database.
"""
