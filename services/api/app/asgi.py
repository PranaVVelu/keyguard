"""Module-level ASGI app for platforms that import `app` directly (Vercel: entrypoint "app.asgi:app").

Configuration comes entirely from environment variables (see docs/DEPLOYMENT.md). Locally, keep using
`uvicorn app.main:create_app --factory`.
"""

from app.main import create_app

app = create_app()
