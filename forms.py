from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField, StringField
from wtforms.validators import InputRequired, URL, Email
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[InputRequired()])
    subtitle = StringField("Subtitle", validators=[InputRequired()])
    img_url = StringField("Blog Image URL", validators=[InputRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[InputRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = StringField(label="Email:", validators=[Email(), InputRequired()])
    password = PasswordField(label="Password:", validators=[InputRequired()])
    name = StringField("Name:")
    submit = SubmitField(label="Sign Up")


class LoginForm(FlaskForm):
    email = StringField(label="Email:", validators=[Email(), InputRequired()])
    password = PasswordField(label="Password:", validators=[InputRequired()])
    submit = SubmitField(label="Log In")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment:", validators=[InputRequired()])
    submit = SubmitField("Submit Comment")
