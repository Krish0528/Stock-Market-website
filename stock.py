from flask import Flask, render_template, redirect, url_for, abort, flash
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired, URL
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegisterForm, LoginForm, RequestForm
import os
import random
import requests


app = Flask(__name__)
app.config['SECRET_KEY'] = "xfyrfouh;.nbcdaw4467ypij;kns5us7"
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE DB
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///user.db"
db = SQLAlchemy()
db.init_app(app)


# CREATE TABLE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))


with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
def home():
    return render_template("index.html")


@app.route('/details', methods=["GET", "POST"])
def details():
    form = RequestForm()
    if form.validate_on_submit():
        symbol = form.symbol.data
        all_data = get_data(symbol)
        return render_template('details.html', data=all_data, success=True)
    return render_template('index.html', form=form)


def get_data(symbol):
    params = {
        'access_key': 'ff356ea7ea774661c73ead3d41201944',
        'symbols': symbol,
    }
    result = requests.get('http://api.marketstack.com/v1/intraday?', params)
    data = result.json()["data"][0]
    return data


# Register new users into the User database
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        # Check if user email is already present in the database.
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        # This line will authenticate the user with Flask-Login
        login_user(new_user)
        return redirect(url_for("details"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('details'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
