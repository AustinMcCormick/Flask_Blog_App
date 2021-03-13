from flask import Blueprint, render_template
from flask_login import login_required, current_user
from . import db 

main = Blueprint('main', __name__)
@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    # print(current_user.is_authenticated)
    # print(vars(current_user))
    # print(current_user.profile_picture)

    if(current_user.public_profile == True):
        return render_template('profile.html', title=current_user.profile_title, name=current_user.name,
        picture=current_user.profile_picture, content=current_user.profile_content, email=current_user.email)
    else: 
        return render_template('profile.html', title="Private User Account for", name=current_user.name,
        picture="/static/imgs/basic_profile_pic.jpg", content="Private", email="Private")
