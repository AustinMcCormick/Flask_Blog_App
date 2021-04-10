from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from project.blueprints.models import User, Blog
from datetime import datetime
from project import db

blog = Blueprint('blog', __name__)

# Blogs Routes
@blog.route('/blogs')
def blogs():
    blogs = Blog.query.order_by(Blog.created_at).all()

    return render_template('blogs.html', blogs=blogs)

@blog.route('/create')
@login_required
def create():
    return render_template('create.html')

@blog.route('/create', methods=['POST'])
@login_required
def create_post():

    title = request.form.get('title')
    content = request.form.get('content')

    new_blog = Blog(title=title, content=content)

    try:
        db.session.add(new_blog)
        db.session.commit() 
        return redirect(url_for('blog.blogs'))

    except Exception as e:
        print(e)
        return redirect(url_for('blog.create'))

@blog.route('/delete/<int:id>')
@login_required
def delete(id):
    blog_to_delete = Blog.query.get_or_404(id)

    try:
        db.session.delete(blog_to_delete)
        db.session.commit()
        return redirect(url_for('blog.blogs'))
    except Exception as e:
        print(e)
        return 'There was a problem deleting that blog'

@blog.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    blog = Blog.query.get_or_404(id)

    if request.method == 'POST':
        blog.title = request.form['title']
        blog.content = request.form['content']

        try:
            db.session.commit()
            return redirect(url_for('blog.blogs'))
        except Exception as e:
            print(e)
            return 'There was an issue updating your task'

    else:
        return render_template('update.html', blog=blog)        
