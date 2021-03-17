from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from.models import User, Blog
from . import db
from datetime import datetime
import os
import stripe
from werkzeug.utils import secure_filename
import hashlib

pub_key = "pk_test_51IViHvAQv6jPBCWoryj1i2f3n9OJXeelJSd4v2eWButhJENzdGMiSgo5Msh01Cv0LyZrUzXrfztSd2iTV358Bnln00BWhOZ3ub"
secret_key = "sk_test_51IViHvAQv6jPBCWo0RvnSBdoWPfGRLFOaTw1vyc1xqwaXbGwYambggt8VQTZAfcgZsWoXUKuz1Y4eg2i3gLlIKUQ00FjuwpTzm"

stripe.api_key = secret_key

UPLOAD_FOLDER = 'project/static/imgs/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
def signup():
    return render_template('signup.html')


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


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@auth.route('/blogs')
def blogs():
    blogs = Blog.query.order_by(Blog.created_at).all()

    if (current_user.is_authenticated and current_user.account_type == 'admin'):
            return render_template('admin_blogs.html', blogs=blogs)
        
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


@auth.route('/store', methods=['GET', 'POST'])
@login_required
def store():
    if (request.method == 'POST'):
        return redirect(url_for('main.profile'))
    else:
        return render_template('store.html', pub_key=pub_key)

@auth.route('/subscribe', methods=['POST'])
@login_required
def subscribe():

    customer = stripe.Customer.create(email=request.form['stripeEmail'], source=request.form['stripeToken'])

    charge = stripe.Charge.create(
        customer=customer.id,
        amount=999,
        currency='usd',
        description='Blog sub purchase'
    )

    print(" Pre ", current_user.subscription_start, " Stripe token ", current_user.sub_token)

    current_user.subscription_start = datetime.now()
    current_user.sub_token = request.form['stripeToken']
    db.session.commit()

    print("post ", current_user.subscription_start, " Stripe token ", current_user.sub_token)


    return redirect(url_for('auth.thanks'))

@auth.route('/thanks', methods=['GET'])
@login_required
def thanks():
    return render_template('thanks.html')
