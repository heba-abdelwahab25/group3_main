from app import create_app, db
from app.models import Product, User
from flask.cli import with_appcontext

app = create_app()

# Create CLI command to create an admin user quickly
@app.cli.command("create-admin")
@with_appcontext
def create_admin():
    name = input("username: ").strip()
    pwd = input("password: ").strip()
    from passlib.hash import argon2
    if not name or not pwd:
        print("missing")
        return
    from app.models import User
    u = User(username=name, password_hash=argon2.using(rounds=4).hash(pwd))
    db.session.add(u)
    db.session.commit()
    print("created", name)

