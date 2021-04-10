from flask import Blueprint, render_template, session
from flask_login import login_required, current_user
from project import db 
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

main = Blueprint('main', __name__)
@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    # print(" Pre ", current_user.subscription_start, " ", current_user.subscribed)

    # Check to see if user is a subscribed non-admin account
    if(current_user.subscribed and not current_user.admin_account):
        # Increase subscription time limit. Lol $9.99 for 90 second subscriptions, I'm not making that kind of website
        sub_end_date = current_user.subscription_start + timedelta(days=90)
        # Check to see if it is past the users subscription time
        if(datetime.now() > sub_end_date):
            # remove subscription from the account
            current_user.subscription_start = None
            current_user.subscribed = False

            # ToDo: make reciept history for accounts
            current_user.sub_token = ''

            db.session.commit()

    # print("Post ", current_user.subscription_start, " ", current_user.subscribed)

    # render profile page for public user
    if(current_user.public_profile == True):
        return render_template('profile.html', title=current_user.profile_title, name=current_user.name,
        picture=current_user.profile_picture, content=current_user.profile_content, email=current_user.email, subscribed=current_user.subscribed)
    # render profile page for private user
    else: 
        return render_template('profile.html', title="Private User Account for", name=current_user.name,
        picture="/static/imgs/basic_profile_pic.jpg", content="Private", email="Private", subscribed=current_user.subscribed)
