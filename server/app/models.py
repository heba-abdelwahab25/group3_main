from . import db
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price_cents = db.Column(db.Integer, nullable=False, default=0)


class ClientActivity(db.Model):
    """Ecommerce-side analytics about clients that use the proxy layer (no dashboard here)."""

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), nullable=True, index=True)
    activity_type = db.Column(db.String(64), nullable=False, index=True)  # health_check|message|purchase|etc
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)