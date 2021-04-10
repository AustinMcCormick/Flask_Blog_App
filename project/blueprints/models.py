from flask_login import UserMixin
from datetime import datetime
from project import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True) 
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    admin_account = db.Column(db.Boolean, default=False)
    public_profile = db.Column(db.Boolean, unique=False, default=True)
    profile_title = db.Column(db.String(100), default="Welcome to my profile page")
    profile_picture = db.Column(db.String(100), default="/static/imgs/basic_profile_pic.jpg")
    profile_content = db.Column(db.String(1000), default="No profile content")
    subscribed = db.Column(db.Boolean, unique=False, default=False)
    subscription_start = db.Column(db.DateTime)
    sub_token = db.Column(db.String(200))
    
class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    product_name = db.Column(db.String(100), nullable=False)
    product_code = db.Column(db.String(50), nullable=False)
    product_img = db.Column(db.String(100), nullable=False)
    product_price = db.Column(db.Integer, nullable=False)
