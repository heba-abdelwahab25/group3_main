from datetime import datetime
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from . import db

_ph = PasswordHasher()


def create_tables(db):
    db.create_all()


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash= db.Column(db.String(255), nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    accounts     = db.relationship("Account", back_populates="owner", lazy="dynamic")

    def set_password(self, raw: str):
        self.password_hash = _ph.hash(raw)

    def check_password(self, raw: str) -> bool:
        try:
            return _ph.verify(self.password_hash, raw)
        except VerifyMismatchError:
            return False


class Account(db.Model):
    __tablename__ = "accounts"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    label      = db.Column(db.String(80), nullable=False, default="Checking")
    balance    = db.Column(db.Integer, nullable=False, default=0)   # cents
    owner      = db.relationship("User", back_populates="accounts")
    transactions = db.relationship("Transaction", back_populates="account", lazy="dynamic")


class Transaction(db.Model):
    __tablename__ = "transactions"
    id           = db.Column(db.Integer, primary_key=True)
    account_id   = db.Column(db.Integer, db.ForeignKey("accounts.id"), nullable=False)
    amount       = db.Column(db.Integer, nullable=False)   # positive=credit, negative=debit (cents)
    description  = db.Column(db.String(200), nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    account      = db.relationship("Account", back_populates="transactions")


class CryptoAuditLog(db.Model):
    """Local per-app crypto audit (mirrors CBOM events)."""
    __tablename__ = "crypto_audit"
    id             = db.Column(db.Integer, primary_key=True)
    event_id       = db.Column(db.String(64), nullable=True)
    crypto_algorithm = db.Column(db.String(80), nullable=False)
    key_length     = db.Column(db.Integer, nullable=True)
    operation      = db.Column(db.String(40), nullable=False)   # handshake|encrypt|decrypt|sign|verify
    status         = db.Column(db.String(20), nullable=False, default="success")
    latency_ms     = db.Column(db.Float, nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow, index=True)
