from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from.models import User, Blog
from . import db
from datetime import datetime


auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    
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


@auth.route('/signup')
@login_required
def signup():
    return render_template('signup.html')

"""
@auth.route('/signup', methods=['POST'])
def signup_post():
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
"""

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@auth.route('/blogs')
def blogs():
    blogs = Blog.query.order_by(Blog.created_at).all()
    return render_template('blogs.html', blogs=blogs)

@auth.route('/create')
@login_required
def create():
    return render_template('create.html')

@auth.route('/create', methods=['POST'])
@login_required
def create_post():

    title = request.form.get('title')
    content = request.form.get('content')

    new_blog = Blog(title=title, content=content)

    try:
        db.session.add(new_blog)
        db.session.commit() 
        return redirect(url_for('auth.blogs'))

    except Exception as e:
        print(e)
        return redirect(url_for('auth.create'))

@auth.route('/delete/<int:id>')
@login_required
def delete(id):
    blog_to_delete = Blog.query.get_or_404(id)

    try:
        db.session.delete(blog_to_delete)
        db.session.commit()
        return redirect(url_for('auth.blogs'))
    except Exception as e:
        print(e)
        return 'There was a problem deleting that blog'


@auth.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    blog = Blog.query.get_or_404(id)

    if request.method == 'POST':
        blog.title = request.form['title']
        blog.content = request.form['content']

        try:
            db.session.commit()
            return redirect(url_for('auth.blogs'))
        except Exception as e:
            print(e)
            return 'There was an issue updating your task'

    else:
        return render_template('update.html', blog=blog)        