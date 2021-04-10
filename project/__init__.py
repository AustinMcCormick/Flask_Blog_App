from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()



def create_app():
    app = Flask(__name__)

    # read in secure information from secrets.txt
    f = open("project/hidden/secrets.txt", "r")
    lines = f.readlines()
    app.config['SECRET_KEY'] = lines[1].strip()
    # Initialize SQLAlchemy
    app.config['SQLALCHEMY_DATABASE_URI'] = lines[4].strip()
    f.close()

    app.config['TEMPLATES_AUTO_RELOAD'] = True

    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from project.blueprints.models import User
    
    @login_manager.user_loader
    def load_user(user_id: int):
        # Find account using id (primary key)
        return User.query.get(user_id)


    # Import feature bluprints
    # main blueprint
    from project.blueprints.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # auth(and profile) blueprint
    from project.blueprints.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    # blog bluprints
    from project.blueprints.blog import blog as blog_blueprint
    app.register_blueprint(blog_blueprint)

    # shop bluprints
    from project.blueprints.shop import shop as shop_blueprint
    app.register_blueprint(shop_blueprint)

    # Debugging tools
    # app.config['SQLALCHEMY_ECHO'] = True

    # Print url_for mapping
    # print(app.url_map)

    # pretty print for large list printing
    # import pprint
    # pprint.pprint(app.config)

    return app