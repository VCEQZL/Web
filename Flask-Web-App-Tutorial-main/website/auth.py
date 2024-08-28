import logging
from flask import Blueprint, Flask, request, jsonify, flash, redirect, url_for, render_template
from flask_cors import CORS
from flask_login import login_user, logout_user, login_required, current_user
import joblib
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from .models import User  # Assuming User model is defined in models.py
from . import db  # Assuming you have initialized SQLAlchemy as 'db'

# Configure logging
logging.basicConfig(level=logging.INFO)  # Set logging level to INFO

app = Flask(__name__)
CORS(app)  # Allow Cross-Origin Resource Sharing

# Load the trained model and TF-IDF vectorizer

auth = Blueprint('auth', __name__)

# def detect_sql_injection(input_str):
#     # Logging the input string
#     logging.info(f"Detecting SQL injection for input string: {input_str}")
    
#     response = requests.post('http://52.172.136.225:4090/', json={'input_str': input_str})
    
#     # Check the response for SQL injection detection
#     if response.status_code == 200:
#         result = response.json()
#         # Logging the response
#         logging.info(f"Response from SQL injection detection API: {result}")
#         return result.get('is_sql_injection', False)
#     else:
#         # Handle API error
#         logging.error("Error while calling SQL injection detection API")
#         return False

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # Validate inputs for SQL injection
        # if detect_sql_injection(email) or detect_sql_injection(first_name) or detect_sql_injection(password1):
        #     flash('SQL Injection detected!', category='error')
        #     logging.warning("SQL Injection detected in sign-up attempt.")
        #     return redirect(url_for('auth.sign_up'))  # Redirect the user back to the sign-up page
        
        # Additional validation checks for other input fields
        # ...

        try:
            # Generate password hash with specified method
            hashed_password = generate_password_hash(password1, method='pbkdf2:sha256')
            new_user = User(email=email, first_name=first_name, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            logging.info(f"New user account created. Username: {first_name}")
            return redirect(url_for('views.home'))
        except IntegrityError:
            flash('Email address is already in use.', category='error')

    return render_template("sign_up.html", user=current_user)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        password = request.form.get('password')

        # Validate inputs for SQL injection
        # if detect_sql_injection(first_name) or detect_sql_injection(password):
        #     flash('SQL Injection detected!', category='error')
        #     logging.warning("SQL Injection detected in login attempt.")
        #     return redirect(url_for('auth.login'))  # Redirect the user back to the login page

        user = User.query.filter_by(first_name=first_name).first()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('Logged in successfully!', category='success')
            return redirect(url_for('views.home'))
        else:
            flash('Invalid Username or password. Please try again.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', category='success')
    return redirect(url_for('views.home'))