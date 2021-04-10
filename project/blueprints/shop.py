from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from project.blueprints.models import User, Product
from datetime import datetime
import stripe
from werkzeug.utils import secure_filename
import hashlib
from project import db


shop = Blueprint('shop', __name__)

# read in secure information from secrets.txt
f = open("project/hidden/secrets.txt", "r")
lines = f.readlines()
pub_key = lines[7].strip()
secret_key = lines[10].strip()
f.close()

stripe.api_key = secret_key

def merge_dicts(dict1, dict2):
    print("Merging dict1 =", type(dict1), "and dict2 =", type(dict2))
    if (isinstance(dict1, list) and isinstance(dict2, list)):
        return dict1 + dict2
    elif (isinstance(dict1, dict) and isinstance(dict2, dict)):
        return dict(list(dict1.items()) + list(dict2.items()))
    return False 


# Store Routes
@shop.route('/store', methods=['GET', 'POST'])
@login_required
def store():
    if (request.method == 'POST'):
        return redirect(url_for('main.profile'))
    else:
        products = Product.query.order_by(Product.id).all()
        return render_template('store.html', pub_key=pub_key, products=products)

@shop.route('/subscribe', methods=['POST'])
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

    return render_template('thanks.html', purchase="the supscription to our blog!")

@shop.route('/add_to_cart', methods=['POST'])
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

@shop.route('/details/<int:id>', methods=['GET', 'POST'])
def Details(id):
    item = Product.query.get_or_404(id)

    return render_template('details.html', item=item)

@shop.route('/cart', methods=['GET'])
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

@shop.route('/checkout', methods=['GET'])
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

@shop.route('/update_cart/<int:code>', methods=['POST'])
def Update_Cart(code):
    if 'cart' not in session and len(session['cart']) <= 0:
        return redirect(url_for('shop.store'))
    
    if request.method == 'POST':
        quantity = request.form.get('quantity')

        try:
            print('  I\'m trying')
            session.modified = True
            for key, item in session['cart'].items():
                if int(key) == code:
                    item['quantity'] = quantity
                    flash('Item quantity updated!')
                    return redirect(url_for('shop.Cart'))

        except Exception as e:
            print(e)

@shop.route('/delete/<int:id>', methods=['POST'])
def Delete(id):
    # print('Deleting item id =', id)
    if 'cart' not in session and len(session['cart']) <= 0:
        return redirect(url_for('shop.store'))

    if request.method == 'POST':
        try:
            session.modified = True
            for key , item in session['cart'].items():
                if int(key) == id:
                    session['cart'].pop(key, None)
                    return redirect(url_for('shop.Cart'))
        except Exception as e:
            print(e)

@shop.route('/purchase', methods=['POST'])
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
@shop.route('/clear')
def Clear():
    try:
        session.clear()
        return redirect(url_for('main.index'))
    except Exception as e:
        print(e)

    return redirect(url_for('main.index'))    

# for clearing the session cart data 
@shop.route('/clear_cart', methods=['POST'])
def Clear_Cart():
    try:
        session.pop('cart', None)
        return redirect(url_for('shop.store'))
    except Exception as e:
        print(e)

    return redirect(url_for('shop.store')) 