"""Manually seed demo accounts from environment variables for local demos only."""
from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv(Path(__file__).resolve().parent / ".env")


def main() -> None:
    if os.environ.get("VULNTRACK_ENV", "").casefold() != "development":
        raise SystemExit("Set VULNTRACK_ENV=development to seed demo users; seeding is disabled by default and in production.")

    import app

    accounts = [
        {
            "username_env": "VULNTRACK_ADMIN_USERNAME",
            "password_env": "VULNTRACK_ADMIN_PASSWORD",
            "role": "Admin",
            "default_username": "admin",
        },
        {
            "username_env": "VULNTRACK_DEVELOPER_USERNAME",
            "password_env": "VULNTRACK_DEVELOPER_PASSWORD",
            "role": "Developer",
            "default_username": "developer",
        },
    ]
    seeded = []
    for account in accounts:
        username_var = account["username_env"]
        password_var = account["password_env"]
        role = account["role"]
        default_username = account["default_username"]
        username = (os.environ.get(username_var, "").strip() or default_username).casefold()
        password = os.environ.get(password_var, "")
        if not password:
            raise SystemExit(f"Set {password_var} before running this script.")
        seeded.append((str(uuid4()), username, generate_password_hash(password), role))

    app.init_db()
    with app.connect_db() as db:
        for user_id, username, password_hash, role in seeded:
            db.execute(
                """INSERT INTO users(id,username,password_hash,role) VALUES(?,?,?,?)
                   ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,role=excluded.role""",
                (user_id, username, password_hash, role),
            )
    print("Seeded demo user accounts:")
    for _, username, _, role in seeded:
        print(f"  {role}: {username}")


if __name__ == "__main__":
    main()
