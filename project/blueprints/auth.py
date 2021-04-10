from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from .models import User, Blog, Product
from project import db
from datetime import datetime
import os
import stripe
from werkzeug.utils import secure_filename
import hashlib


auth = Blueprint('auth', __name__)

# read in secure information from secrets.txt
f = open("project/hidden/secrets.txt", "r")
lines = f.readlines()
UPLOAD_FOLDER = lines[13].strip()
string_allowed_extensions = lines[16]
ALLOWED_EXTENSIONS = set(string_allowed_extensions.split(", "))
f.close()


# Methods 
def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Account Routes
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        # find the users account
        user = User.query.filter_by(email=email).first()

        # Check to make sure it exists
        if not user or not check_password_hash(user.password, password):     
            flash('Please check your login details and try again')
            # If ethier password or email check fails reload the login page
            return redirect(url_for('auth.login')) 

        # Users that make it to this point have verified emails / passwords
        login_user(user, remember=remember)

        # import pprint
        # pprint.pprint(vars(current_user))
        
        return redirect(url_for('main.profile'))
    else:
        return render_template('login.html')

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')

        # Check to see if the email address has already been used in the DB
        user = User.query.filter_by(email=email).first()

        # If the user email already exists redirect back to signup page
        if user: 
            flash('Email address already exists')
            return redirect(url_for('auth.signup'))

        # Create new user for unused email addresses and hash password
        new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

        # Add user to Database
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('auth.login'))
    else:
        return render_template('signup.html')

@auth.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('main.index'))

# Profile Routes
@auth.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No image selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            # upload acceptable profile picture
            hs = hashlib.sha256(current_user.email.encode('utf-8')).hexdigest()
            file.save(os.path.join(UPLOAD_FOLDER, hs))
            
            current_user.profile_picture = '/static/imgs/' + hs
            db.session.commit()
            return redirect(url_for('main.profile'))
        else:
            flash('Allowed image types are -> png, jpg, jpeg')
            return redirect(request.url)
            
    else:  
        return render_template('upload.html') 

@auth.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        name = request.form.get('name')
        profile_content = request.form.get('profile_content')
        public_profile = request.form.get('public_profile') 
        email = request.form.get('email') 

        if(public_profile == 'False'):
            current_user.public_profile = False
        else:
            current_user.public_profile = True
        
        if(name != ''):
            current_user.name = name

        if(email != ''):
            user = User.query.filter_by(email=email).first()
            # If the user email already exists redirect back to update profile page
            if user: 
                flash('Email address already exists')
                return redirect(url_for('auth.update_profile'))
            else:
                current_user.email = email

        if(profile_content != ''):
            current_user.profile_content = profile_content
        
        db.session.commit()

        return redirect(url_for('main.profile'))
    else:
        return render_template('update_profile.html')
