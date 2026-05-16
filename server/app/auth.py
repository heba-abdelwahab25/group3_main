from flask import Blueprint, render_template, request, redirect, url_for, flash
from . import db
from .models import User
from flask_login import login_user, logout_user, current_user
from passlib.hash import argon2
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length

bp = Blueprint("auth", __name__, url_prefix="/auth")

class RegisterForm(FlaskForm):
    username = StringField("username", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("password", validators=[DataRequired(), Length(min=8)])

class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])

@bp.route("/register", methods=["GET","POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            return render_template("register.html", form=form)
        # Hash password using Argon2
        pw_hash = argon2.using(rounds=4).hash(password)
        user = User(username=username, password_hash=pw_hash)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html", form=form)

@bp.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and argon2.verify(password, user.password_hash):
            login_user(user)
            flash("Logged in", "success")
            return redirect(url_for("main.index"))
        flash("Invalid credentials", "error")
    return render_template("login.html", form=form)

@bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("main.index"))

