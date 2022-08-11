from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from flask_migrate import Migrate
from functools import wraps
from sqlalchemy import MetaData
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('VAR1')

ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
uri = os.getenv("DATABASE_URL", "sqlite:///blog.db")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=convention)
db = SQLAlchemy(app, metadata=metadata)

migrate = Migrate(app, db, render_as_batch=True)
migrate.init_app(app, db, render_as_batch=True)

login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    comments = relationship("Comment", back_populates="post")


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    name = db.Column(db.String(1000), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="account_user")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    account_user = relationship("User", back_populates="comments")
    account_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


# db.drop_all()
db.create_all()
db.session.commit()


# Create specific-user--only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


initial = True
if initial:
    if current_user:
        current_user.is_authenticated = False
        initial = False


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        user = User()
        user.email = form.email.data
        password = form.password.data
        hashed = generate_password_hash(password=password, salt_length=8, method='pbkdf2:sha256')
        user.password = hashed
        user.name = form.name.data

        if User.query.filter_by(email=user.email).first():
            flash(f"User {user.email} already exists!", 'info')
            flash("Log in instead.", 'info')
        else:
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash(f"Wrong Password.", 'error')
                flash("Please try again.", 'error')
        else:
            flash(f"User does not exist!", 'error')
            flash("Register instead.", 'error')

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.all()
    form = CommentForm()
    if form.validate_on_submit():
        comment = form.comment.data
        if current_user.is_anonymous:
            new_comment = Comment(comment=comment, post=requested_post, account_user_id=0)
        else:
            new_comment = Comment(comment=comment, account_user=current_user, post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post=requested_post, form=form, all_comments=comments, post_id=post_id))
    return render_template("post.html", post=requested_post, form=form, all_comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    if post.author_id == current_user.id or current_user.id == 1:
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            author=current_user,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

        return render_template("make-post.html", form=edit_form, is_edit=True)
    else:
        return abort(403)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    if post_to_delete.author_id == current_user.id or current_user.id == 1:
        comments = Comment.query.all()
        for comment in comments:
            if comment.post_id == post_id:
                delete_comment(comment_id=comment.id, post_id=post_id)

        db.session.delete(post_to_delete)
        db.session.commit()

        for post in BlogPost.query.all():
            if post.id > int(post_id):
                post.id -= 1
                db.session.commit()

        for comment in Comment.query.all():
            if comment.post_id > int(post_id):
                comment.post_id -= 1
                db.session.commit()

        return redirect(url_for('get_all_posts'))
    else:
        return abort(403)


@app.route("/delete/<int:post_id>/<int:comment_id>")
@login_required
def delete_comment(comment_id, post_id):
    comment_to_delete = Comment.query.get(comment_id)
    if comment_to_delete.account_user_id == current_user.id or current_user.id == 1:
        db.session.delete(comment_to_delete)
        db.session.commit()
        for comment in Comment.query.all():
            if comment.id > int(comment_id):
                comment.id -= 1
                db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    else:
        return abort(403)


if __name__ == "__main__":
    app.run(debug=True)
