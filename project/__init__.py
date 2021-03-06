from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    # Initialize SQLAlchemy
    app.config['SECRET_KEY'] = 'SneakySnake'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://Austin:One23456@localhost/flask_auth_appDB'
    
    # app.config['SQLALCHEMY_ECHO'] = True

    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User
    
    @login_manager.user_loader
    def load_user(user_id: int):
        # Find account using id (primary key)
        return User.query.get(user_id)

    # Authorized role blueprint
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # Non-Authorized role blueprint
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # Print url_for mapping
    # print(app.url_map)

    # pretty print for large list printing
    # import pprint
    # pprint.pprint(app.config)

    return app