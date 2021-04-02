from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from.models import User, Blog, Product
from . import db
from datetime import datetime
import os
import stripe
from werkzeug.utils import secure_filename
import hashlib

auth = Blueprint('auth', __name__)

pub_key = "pk_test_51IViHvAQv6jPBCWoryj1i2f3n9OJXeelJSd4v2eWButhJENzdGMiSgo5Msh01Cv0LyZrUzXrfztSd2iTV358Bnln00BWhOZ3ub"
secret_key = "sk_test_51IViHvAQv6jPBCWo0RvnSBdoWPfGRLFOaTw1vyc1xqwaXbGwYambggt8VQTZAfcgZsWoXUKuz1Y4eg2i3gLlIKUQ00FjuwpTzm"

stripe.api_key = secret_key

UPLOAD_FOLDER = 'project/static/imgs/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

# Methods 
def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def merge_dicts(dict1, dict2):
    print("Merging dict1 =", type(dict1), "and dict2 =", type(dict2))
    if (isinstance(dict1, list) and isinstance(dict2, list)):
        return dict1 + dict2
    elif (isinstance(dict1, dict) and isinstance(dict2, dict)):
        return dict(list(dict1.items()) + list(dict2.items()))
    return False 


# Account Routes
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
    session.clear()
    logout_user()
    return redirect(url_for('main.index'))

# Blogs Routes
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

# Store Routes
@auth.route('/store', methods=['GET', 'POST'])
@login_required
def store():
    if (request.method == 'POST'):
        return redirect(url_for('main.profile'))
    else:
        products = Product.query.order_by(Product.id).all()
        return render_template('store.html', pub_key=pub_key, products=products)

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

    # print(" Pre ", current_user.subscription_start, " Stripe token ", current_user.sub_token, " ", current_user.subscribed)

    current_user.subscribed = True
    current_user.subscription_start = datetime.now()
    current_user.sub_token = request.form['stripeToken']
    db.session.commit()

    # print("Post ", current_user.subscription_start, " Stripe    ", current_user.sub_token, " ", current_user.subscribed)

    return render_template('thanks.html', purchase=" for the supscription")

@auth.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    try:
        product_quantity = request.form.get('quantity')
        product_id = request.form.get('id')
        product = Product.query.get_or_404(product_id)

        # print("added ", product_quantity, " ", product.product_name, " code: ", product.product_code, " to your ShoppingCart ID = ", product.id)

        if (product_quantity and product and request.method == 'POST'):
            dict_Items = {product_id:{
                'name': product.product_name, 
                'image': product.product_img,
                'price': product.product_price, 
                'quantity': product_quantity, 
                'discount': 0,
                'code': product.product_code
            }}

            # Checks to see if the user has already started a cart.
            if ('cart' in session):
                print("Updating Existing Cart For Session")
                
                import pprint
                pprint.pprint(session['cart'])
                
                # If the product is in the cart, update the quantity. 
                if (product_id in session['cart']):
                    print("  - Updating Cart Item Quantity For: ", product.product_name)
                # If the product is not already in the cart, add the item
                else:
                    print("  - New Cart Item ", product.product_name, " ( x", product_quantity, ")")
                    session['cart'] = merge_dicts(session['cart'], dict_Items)
            else:
                print("Creating Cart For Session")
                # In this block, the user has not started a cart, so we start it for them and add the product. 
                print("dict_Items type =", type(dict_Items))
                session['cart'] = dict_Items
                print("      cart type =", type(session['cart']))

    except Exception as e:
        print(e)
    finally:
        return redirect(request.referrer)

@auth.route('/details/<int:id>', methods=['GET', 'POST'])
def Details(id):
    item = Product.query.get_or_404(id)

    return render_template('details.html', item=item)

@auth.route('/cart', methods=['GET'])
def Cart():
    if('cart' in session):
        subtotal = 0
        grandtotal = 0
        before_tax = 0

        for key, product in session['cart'].items():
            discount = (product['discount']/100 * float(product['price']))
            subtotal += float(product['price']) * int(product['quantity'])
            subtotal -= discount
            before_tax += subtotal

        
        tax = subtotal * 0.12
        grandtotal = float(subtotal * 1.12)
        grandtotal = float("{:.2f}".format(grandtotal))

        return render_template('cart.html', before_tax=before_tax, tax=tax, grandtotal=grandtotal)    
    else: 
        # no cart to view
        return redirect(request.referrer)

@auth.route('/checkout', methods=['GET'])
def Checkout():
    if('cart' in session):
        total = 0
        grandtotal = 0
        products = ''

        for key, product in session['cart'].items():
            discount = (product['discount']/100 * float(product['price']))
            total += float(product['price']) * int(product['quantity'])
            total -= discount
            grandtotal = float(float("{:.2f}".format(total * 1.12)))
            products = products + product['name'] + ": " + product['code'] +  " x " + product['quantity']  + "\n"
        
        tax = float("{:.2f}".format(total * 0.12))
        grandtotal = float(total * 1.12)
        grandtotal = float("{:.2f}".format(grandtotal))
        charge_amount = grandtotal * 100
        charge_amount = int(charge_amount)

        return render_template('checkout.html', products=products, total=total, grandtotal=grandtotal, charge_amount=charge_amount, tax=tax, pub_key=pub_key)    
    else: 
        # no cart to checkout
        return redirect(request.referrer)

@auth.route('/update_cart/<int:code>', methods=['POST'])
def Update_Cart(code):
    if 'cart' not in session and len(session['cart']) <= 0:
        return redirect(url_for('auth.shop'))
    
    if request.method == 'POST':
        quantity = request.form.get('quantity')

        try:
            print('  I\'m trying')
            session.modified = True
            for key, item in session['cart'].items():
                if int(key) == code:
                    item['quantity'] = quantity
                    flash('Item quantity updated!')
                    return redirect(url_for('auth.Cart'))

        except Exception as e:
            print(e)

@auth.route('/delete/<int:id>', methods=['POST'])
def Delete(id):
    print('Deleting item id =', id)
    if 'cart' not in session and len(session['cart']) <= 0:
        return redirect(url_for('auth.shop'))

    if request.method == 'POST':
        try:
            session.modified = True
            for key , item in session['cart'].items():
                if int(key) == id:
                    session['cart'].pop(key, None)
                    return redirect(url_for('auth.Cart'))
        except Exception as e:
            print(e)

@auth.route('/purchase', methods=['POST'])
def Purchase():
    charge_amount = request.form.get('charge_amount') 
    charge_description = request.form.get('charge_description')

    customer = stripe.Customer.create(email=request.form['stripeEmail'], source=request.form['stripeToken'])

    charge = stripe.Charge.create(
        customer=customer.id,
        amount=charge_amount,
        currency='usd',
        description=charge_description
    )

    session.pop('cart', None)

    return render_template('thanks.html', purchase=charge_description)

# for clearing the session login / cart data 
@auth.route('/clear')
def Clear():
    try:
        session.clear()
        return redirect(url_for('main.index'))
    except Exception as e:
        print(e)

    return redirect(url_for('main.index'))    

# for clearing the session cart data 
@auth.route('/clear_cart', methods=['POST'])
def Clear_Cart():
    try:
        session.pop('cart', None)
        return redirect(url_for('auth.store'))
    except Exception as e:
        print(e)

    return redirect(url_for('auth.store')) 