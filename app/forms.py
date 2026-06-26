from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import (
    BooleanField,
    FileField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, EqualTo, ValidationError

from app.models import User


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])
    role = SelectField(
        "I am a",
        choices=[
            ("student", "Student"),
            ("senior_student", "Senior Student"),
            ("teacher", "Teacher"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("Username is already taken. Please choose another one!")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    image = FileField("Image", validators=[FileAllowed(["jpg", "png"])])
    caption = TextAreaField("Caption", validators=[DataRequired()])
    is_anonymous = BooleanField("Anonymous")
    submit = SubmitField("Post")


class UpdatePostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    image = FileField("Image", validators=[FileAllowed(["jpg", "png"])])
    caption = TextAreaField("Caption", validators=[DataRequired()])
    is_anonymous = BooleanField("Anonymous")
    submit = SubmitField("Update")


class DeletePostForm(FlaskForm):
    submit = SubmitField("Delete")


class QuestionForm(FlaskForm):
    question = StringField("Title", validators=[DataRequired()])
    option1 = StringField("Option1", validators=[DataRequired()])
    option2 = StringField("Option2", validators=[DataRequired()])
    option3 = StringField("Option3", validators=[DataRequired()])
    option4 = StringField("Option4", validators=[DataRequired()])
    answer = StringField("Answer", validators=[DataRequired()])
    submit = SubmitField("Question")


class UpdateAccountForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    profile_image = FileField("Profile Image", validators=[FileAllowed(["jpg", "png"])])
    occupation = StringField("Occupation", validators=[DataRequired()])
    submit = SubmitField("Update")

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user is not None:
                raise ValidationError("Username is already taken. Please choose another one!")


class DeleteAccountForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Delete Account")


class CommentForm(FlaskForm):
    content = TextAreaField("Comment", validators=[DataRequired()])
    submit = SubmitField("Post Comment")


class EditCommentForm(FlaskForm):
    content = TextAreaField("Comment", validators=[DataRequired()])
    submit = SubmitField("Edit Comment")


class DeleteCommentForm(FlaskForm):
    submit = SubmitField("Delete")


class LikeForm(FlaskForm):
    submit = SubmitField("Like")


class UnlikeForm(FlaskForm):
    submit = SubmitField("Unlike")


class ChatForm(FlaskForm):
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")


class SearchForm(FlaskForm):
    q = StringField("Search", validators=[DataRequired()], default="")


class ChangeRoleForm(FlaskForm):
    role = SelectField(
        "New Role",
        choices=[
            ("student", "Student"),
            ("senior_student", "Senior Student"),
            ("teacher", "Teacher"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Update Role")
