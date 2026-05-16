from app import create_app, db
from app.models import Product, User, ClientActivity
from passlib.hash import argon2

app = create_app()

with app.app_context():
    db.create_all()
    # add sample products if none exist
    if Product.query.count() == 0:
        p1 = Product(name="Toy Robot", description="A small robot", price_cents=1999)
        p2 = Product(name="Puzzle Box", description="A wooden puzzle", price_cents=1299)
        db.session.add_all([p1,p2])
        db.session.commit()
    print("DB initialized.")

