import os
from flask import Flask, render_template, request, flash, redirect, url_for, g, current_app , abort
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin

from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData, or_, and_

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from flask_wtf.file import FileField, FileRequired, FileAllowed

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename

import bcrypt

import os
import secrets
from PIL import Image

import datetime
from datetime import datetime
from pytz import timezone
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///careerconnect.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['POSTS_PER_PAGE'] = 4
app.config['UPLOAD_FOLDER'] = 'static/posts'
app.config['ALLOWED_IMAGE_EXTENSIONS'] = ['JPG', 'PNG']
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

Bootstrap(app)
db = SQLAlchemy(app)

migrate = Migrate(app, db, render_as_batch=True)

login = LoginManager(app)
login.login_view = 'login'
login.init_app(app)


# -------------------------------  MODELS ---------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chat_text = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_image = db.Column(db.String(128), default='def.jpg')

    posts = db.relationship('Post', back_populates='user', lazy='subquery')
    comments = db.relationship('Comment', backref='user', lazy='dynamic')
    likes = db.relationship('Like', backref='user', lazy='dynamic')

    # <-- MIGUEL GRINBERG --> 
    followers = db.relationship('Follow',
                                foreign_keys='Follow.followed_id',
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')

    following = db.relationship('Follow',
                                foreign_keys='Follow.follower_id',
                                backref=db.backref('follower', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')

    # <-------------------->

    chats_sent = db.relationship('Chat', foreign_keys=[Chat.sender_id], backref='sender_user', lazy='dynamic')
    chats_received = db.relationship('Chat', foreign_keys=[Chat.receiver_id], backref='receiver_user', lazy='dynamic')

    follower_count = db.Column(db.Integer, default=0)
    following_count = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_following(self, user):
        return self.following.filter(Follow.followed_id == user.id).count() > 0

    def follow(self, user):
        if not self.is_following(user):
            existing_follow = Follow.query.filter_by(follower_id=self.id, followed_id=user.id).first()

            if not existing_follow:
                new_follow = Follow(follower_id=self.id, followed_id=user.id)

                db.session.add(new_follow)
                user.follower_count += 1
                self.following_count += 1
                db.session.commit()

            flash('User is already following this user !! ', 'danger')


    def unfollow(self, user):
        if self.is_following(user):
            existing_follow = Follow.query.filter_by(follower_id=self.id, followed_id=user.id).first()

            if existing_follow:
                db.session.delete(existing_follow)
                user.follower_count -= 1
                self.following_count -= 1
                db.session.commit()

            flash('You are not following this user !!', 'danger')


    def has_liked_post(self, post):
        return Like.query.filter(
            Like.user_id == self.id,
            Like.post_id == post.id
        ).count() > 0

    def like_post(self, post):
        if not self.has_liked_post(post):
            like = Like(user_id=self.id, post_id=post.id)
            db.session.add(like)

    def unlike_post(self, post):
        if self.has_liked_post(post):
            Like.query.filter_by( user_id=self.id, post_id=post.id).delete()

    def send_chat(self, receiver, chat_text):
        new_chat = Chat(sender=self, receiver=receiver, chat_text=chat_text)
        db.session.add(new_chat)
        db.session.commit()

    def get_chats_with(self, other_user):
        return Chat.query.filter(
            (Chat.sender == self and Chat.receiver == other_user) |
            (Chat.sender == other_user and Chat.receiver == self)
        ).order_by(Chat.timestamp)


    def __repr__(self):
        return f"User('{self.id}', '{self.username}', '{self.profile_image}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)

    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone('Asia/Kolkata')))
    last_updated = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')), onupdate=datetime.now(timezone('Asia/Kolkata')))

    status = db.Column(db.String(20))

    caption = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(128))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='posts', lazy=True)

    likes = db.relationship('Like', backref='posts', lazy='dynamic')
    comments = db.relationship('Comment', backref='posts', lazy='dynamic')

    def __repr__(self):
        return f"Post('{self.id}', '{self.title}', '{self.timestamp}')"


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')))

    def __repr__(self):
        return f"Like('{self.id}')"


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone('Asia/Kolkata')))
    last_edited = db.Column(db.DateTime, default=datetime.now(timezone('Asia/Kolkata')), onupdate=datetime.now(timezone('Asia/Kolkata')))

    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f"Comment('{self.id}', '{self.timestamp}')"


class Follow(db.Model):
    __table_args__ = (db.UniqueConstraint('follower_id', 'followed_id', name='unique_constraint_follow'),)

    id = db.Column(db.Integer, primary_key=True)

    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, primary_key=True)

    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, primary_key=True)

    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone('Asia/Kolkata')))

    def __repr__(self):
        return f"Follow('{self.id}')"

# ------------------------------------------------------------------------

# for handling images.

# 1. handling POSTS
def save_post(post_image):
    hex_random = secrets.token_hex(8)
    _, file_extension = os.path.splitext(post_image.filename)
    post_filename = hex_random + file_extension
    post_path = os.path.join(current_app.root_path, 'static/posts', post_filename)
    
    op_size = (75, 75)

    try: 
        i = Image.open(post_image)
        i.thumbnail(op_size)
        i.save(post_path)

    except Exception as e:
        flash(f'Couldn\'t save post image due to : {e}', 'danger')

    return post_filename


# 2. handling PROFILE PICS
def save_profile(prof_image):
    hex_random = secrets.token_hex(8)
    _, file_extension = os.path.splitext(prof_image.filename)
    profile_filename = hex_random + file_extension
    profile_path = os.path.join(current_app.root_path, 'static/profile', profile_filename)
    
    op_size = (75,75)

    try: 
        i = Image.open(prof_image)
        i.thumbnail(op_size)
        i.save(profile_path)

    except Exception as e:
        flash(f'Couldn\'t save profile image due to : {e}', 'danger')

    return profile_filename


@login.user_loader
def load_user(user_id):
    # return the user object for the user with the given user_id
    return User.query.get(int(user_id))

# -------------------------------  FORMS ---------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken. Please choose another one !!')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png'])])
    caption = TextAreaField('Caption', validators=[DataRequired()])
    submit = SubmitField('Post')

class UpdatePostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png'])])
    caption = TextAreaField('Caption', validators=[DataRequired()])
    submit = SubmitField('Update')

class DeletePostForm(FlaskForm):
    submit = SubmitField('Delete')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    profile_image = FileField('Profile Image', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user is not None:
                raise ValidationError('Username is already taken. Please choose another one !!')


class DeleteAccountForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Delete Account')


class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post Comment')

class EditCommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Edit Comment')

class DeleteCommentForm(FlaskForm):
    submit = SubmitField('Delete')

class LikeForm(FlaskForm):
    submit = SubmitField('Like')

class UnlikeForm(FlaskForm):
    submit = SubmitField('Unlike')

class ChatForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

class UnfollowForm(FlaskForm):
    submit = SubmitField('Unfollow')

class SearchForm(FlaskForm):
    q = StringField('Search', validators=[DataRequired()], default="")


# -------------------------------  ROUTES ---------------------------------------
# -------------------------------------------------------------------------------
# -------------------------------------------------------------------------------

# WELCOME page
@app.route('/')
def welcome():
    return render_template('welcome.html')

# REGISTRATION page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegistrationForm()

    if form.validate_on_submit():
        # check if the username is already registered or the username is already taken
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('User already registered !!', 'danger')
            return redirect(url_for('login'))

        if form.password.data != form.confirm_password.data:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        # Create a new user object and set their password
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password_hash=hashed_password)

        # 2nd way if not using hashed_paaword
        # new_user.set_password(form.password.data)
        
        # Add the user object to the database and commit the changes
        db.session.add(new_user)
        db.session.commit()
        
        flash('Successfully Registered !!', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# LOGIN page
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        # user.is_active = True
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Successfully logged in !!', 'success')

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('feed'))
        else:
            flash('Login Unsuccessful !!', 'danger')
            flash('Invalid username or password !!', 'danger')
    return render_template('login.html', title='Login', form=form)


# LOGOUT page
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out Successfully !!' , 'success')
    return redirect(url_for('login'))

# --------------------------------------------------------------------------------

# FEED page
@app.route('/feed')
@login_required
def feed():

    # Get a list of all posts by the user's followers, ordered by the timestamp
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    print(posts)
    return render_template('feed.html', title='Feed page', posts=posts, timezone=timezone)

# --------------------------------------------------------------------------------

# PROFILE page
@app.route("/profile/<username>")
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)

    posts = Post.query.filter_by(user_id=user.id).order_by(Post.timestamp.desc()).paginate(page=page, per_page=5)

    likes = len(Like.query.filter_by(user_id = user.id).all())
    comments = len(Comment.query.filter_by(user_id = user.id).all())


    published_posts_count = Post.query.filter_by(user_id=user.id).count()

    follow_form = ChatForm()
    unfollow_form = UnfollowForm()

    followers_count = user.followers.count()
    following_count = user.following.count()

    is_following = current_user.is_following(user)

    like_form = LikeForm()
    unlike_form = UnlikeForm()


    return render_template('profile.html', likes=likes,comments=comments, user=user, posts=posts, timezone=timezone, db=db, follow_form=follow_form, unfollow_form=unfollow_form, followers_count=followers_count, following_count=following_count, is_following=is_following, like_form=like_form, unlike_form=unlike_form, published_posts_count=published_posts_count)


# CRUD on posts -----------------------------------------------------------------
# -------------------------------------------------------------------------------

# CREATE_POST page
@app.route("/post/create_post", methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()

    if form.validate_on_submit():
        image_file = None
        if form.image.data:
            image_file = save_post(form.image.data)

        post = Post(title=form.title.data, caption=form.caption.data, image = image_file, user_id=current_user.id)

        db.session.add(post)
        db.session.commit()

        flash('Post created !!', 'success')
        return redirect(url_for('profile', username=current_user.username))

    return render_template('create_post.html', title='Create Post page', form=form)



# UPDATE_POST page
@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user != current_user:
        abort(403)

    form = UpdatePostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.caption = form.caption.data

        if form.image.data:
            # first delete the existing image in the post
            print(post.image)
            if post.image:
                try:
                    os.remove(os.path.join(current_app.root_path, 'static/posts', post.image))
                except Exception as e : 
                    flash(f'Couldn\'t delete existing POST image due to {e}!!', 'danger' )
                    return redirect(url_for('update_post', post_id=post.id))

            # saving new image
            image_file = save_post(form.image.data)
            post.image_file = image_file

        post.last_updated = datetime.now(timezone('Asia/Kolkata'))

        try:
            db.session.commit()

        except Exception as e:
            flash(f'Couldn\'t save new POST image due to {e}!!', 'danger')
            db.session.rollback()
        
        flash('Post updated !!', 'success')
        print(post)
        return redirect(url_for('profile', username=current_user.username))

    elif request.method == 'GET':
        form.title.data = post.title
        form.caption.data = post.caption

    return render_template('update_post.html', form=form)



# DELETE_POST page
@app.route("/post/<int:post_id>/delete", methods=['GET','POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user != current_user:
        abort(403)

    form = DeletePostForm()

    if form.validate_on_submit():
        # delete the likes related to the post
        db.session.query(Like).filter_by(post_id=post_id).delete()

        # delete the comments associated with the post 
        db.session.query(Comment).filter_by(post_id=post_id).delete()

        db.session.delete(post)
        db.session.commit()

        flash('Post Deleted !!', 'success')
        return redirect(url_for('profile', username=current_user.username))

    return render_template('delete_post.html', post=post, form=form)


# CRUD on users / accounts -------------------------------------------------------
# --------------------------------------------------------------------------------

# UPDATE account page
@app.route("/update_account", methods=['GET', 'POST'])
@login_required
def update_account():
    form = UpdateAccountForm()

    if form.validate_on_submit():
        if form.profile_image.data:
            picture_file = save_profile(form.profile_image.data)
            current_user.profile_image = picture_file

        current_user.username = form.username.data
        db.session.commit()

        flash('Account updated !!', 'success')
        return redirect(url_for('profile', username=current_user.username))

    elif request.method == 'GET':
        form.username.data = current_user.username

    return render_template('update_account.html', title='Update Account page',  form=form)


# DELETE account page
@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    form = DeleteAccountForm()

    if form.validate_on_submit():
        if current_user.check_password(form.password.data):
            # delete all the posts associated with the users
            db.session.query(Post).filter(Post.user_id == current_user.id).delete()

            db.session.delete(current_user)
            db.session.commit()

            logout_user()

            flash('Account deleted !!', 'success')
            return redirect(url_for('login'))

        else:
            flash('Incorrect Password !!', 'danger')
    return render_template('delete_account.html', form=form)


# FOLLOW / UNFOLLOW functionality -----------------------------------------------
# -------------------------------------------------------------------------------

# FOLLOW route
@app.route("/follow/<username>", methods=['POST'])
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()

    if user is None:
        flash(f'User {username} not found !!', 'danger')
        return redirect(url_for('profile', username=username))

    if user == current_user:
        flash('You cannot follow yourself !!', 'danger')
        return redirect(url_for('profile', username=username))

    if current_user.is_following(user):
        flash(f'You are already following {username} !!', 'danger')
        return redirect(url_for('profile', username=username))

    current_user.follow(user)
    db.session.flush()

    flash(f'You are now following {username} !!', 'success')
    return redirect(url_for('profile', username=username))


# UNFOLLOW route
@app.route("/unfollow/<username>", methods=['POST'])
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()

    if user is None:
        flash(f'User {username} not found !!', 'danger')
        return redirect(url_for('profile',username=username))

    if user == current_user:
        flash('You cannot unfollow yourself !!', 'danger')
        return redirect(url_for('profile',username=username))

    if not current_user.is_following(user):
        flash(f'You are not following {username} !!', 'danger')
        return redirect(url_for('profile',username=username))

    current_user.unfollow(user)
    db.session.flush()
    
    flash(f'You are no longer following {username} !! ', 'success')
    return redirect(url_for('profile', username=username))


# FOLLOWERS page
@app.route('/followers/<username>', methods=['GET','POST'])
@login_required
def followers(username):
    user = User.query.filter_by(username=username).first()

    if user is None: 
        flash('User not found !!', 'danger')
        redirect(url_for('profile', username=username))
    
    followers = User.query.join(Follow, User.id == Follow.follower_id).filter(Follow.followed_id == user.id).order_by(Follow.timestamp.desc()).all()

    followers = [x for x in followers if x != user]

    follow_form = ChatForm()
    unfollow_form = UnfollowForm()

    return render_template('followers.html', user=user, followers=followers, username=username, follow_form=follow_form, unfollow_form=unfollow_form)


# FOLLOWING page
@app.route('/following/<username>', methods=['GET','POST'])
@login_required
def following(username):
    user = User.query.filter_by(username=username).first()

    if user is None: 
        flash('User not found !!', 'danger')
        redirect(url_for('profile', username=username))

    following = User.query.join(Follow, User.id == Follow.followed_id).filter(Follow.follower_id == user.id).order_by(Follow.timestamp.desc()).all()

    following = [x for x in following if x != user]

    follow_form = ChatForm()
    unfollow_form = UnfollowForm()

    return render_template('following.html', user=user, following=following, username=username, follow_form=follow_form, unfollow_form=unfollow_form)


# LIKE / UNLIKE functionality ----------------------------------------------------
# --------------------------------------------------------------------------------

# LIKE route
@app.route("/likes/user/<username>", methods=['GET', 'POST'])
@login_required
def likes_of_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    likes = Like.query.filter_by(user_id = user.id).all()
    posts = []
    for like in likes:
        posts.append(like.posts)
    print(posts)
    return render_template('all_likes.html', title='All likes page', posts=posts, timezone=timezone)

@app.route("/comments/user/<username>", methods=['GET', 'POST'])
@login_required
def comments_of_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    comments = Comment.query.filter_by(user_id = user.id).all()
    posts = []
    for comment in comments:
        if comment.posts not in posts:
            posts.append(comment.posts)
    print(posts)
    return render_template('all_comments.html', title='All comments page', posts=posts, timezone=timezone)


@app.route("/like/<int:post_id>" , methods=['GET','POST'])
@login_required
def like(post_id):
    post = Post.query.filter_by(id=post_id).first_or_404()

    current_user.like_post(post)
    db.session.commit()

    flash(f'You have liked the post "{post.title}" made by {post.user.username} !!', 'success')

    return redirect(url_for('feed'))


# UNLIKE route 
@app.route('/unlike/<int:post_id>', methods=['POST', 'GET'])
@login_required
def unlike(post_id):
    post = Post.query.filter_by(id=post_id).first_or_404()

    current_user.unlike_post(post)
    db.session.commit()

    flash(f'You have unliked the post "{post.title}" made by {post.user.username} !!', 'danger')

    return redirect(url_for('feed'))


# CRUD on comments ---------------------------------------------------------------
# --------------------------------------------------------------------------------

# add COMMENT page
@app.route("/post/<int:post_id>/comment", methods=['GET', 'POST'])
@login_required
def comment(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()

    form = CommentForm()

    if form.validate_on_submit():
        new_comment = Comment(content=form.content.data, user_id=current_user.id, post_id=post_id)

        db.session.add(new_comment)
        db.session.commit()

        flash('Comment added !!', 'success')

        return redirect(url_for('comment', post_id=post_id))
    return render_template('comment.html', form=form, post_id=post_id, comments=comments, post=post, timezone=timezone)


# edit COMMENT page
@app.route('/post/<int:post_id>/comment/<int:comment_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_comment(post_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user != current_user:
        abort(403)

    form = EditCommentForm()

    if form.validate_on_submit():
        comment.content = form.content.data
        db.session.commit()

        flash('Comment edited !!', 'success')
        return redirect(url_for('comment', post_id=comment.post_id))

    elif request.method == 'GET':
        form.content.data = comment.content

    return render_template('edit_comment.html', form=form , post_id=comment.post_id, comment_id = comment.id)


# DELETE comment page
@app.route("/post/<int:post_id>/comment/<int:comment_id>/delete", methods=['GET','POST'])
@login_required
def delete_comment(post_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user != current_user:
        abort(403)

    form = DeleteCommentForm()

    if form.validate_on_submit():
        db.session.delete(comment)
        db.session.commit()

        flash('Comment deleted !!', 'success')
        return redirect(url_for('comment', post_id=post_id))

    return render_template('delete_comment.html', form=form, post_id=comment.post_id, comment_id = comment.id, comment=comment)

# --------------------------------------------------------------------------------

# SEARCH page (statements for debugging)
@app.route("/search", methods=['GET', 'POST'])
@login_required
def search():
    form = SearchForm()

    if form.validate_on_submit():
        query = form.q.data
        print(f"Search query: {query}")
        users = []
        if query: 

            users = User.query.filter(User.username.like(f"%{query}%")).all()
            posts = Post.query.filter(or_(Post.caption.like(f"%{query}%"), Post.title.like(f"%{query}%") )).all()
            print(f"Search results: {users}")
            print(f"Search results: {posts}")

            published_posts_count = db.session.query(Post).join(User).filter(User.username.in_([user.username for user in users]), Post.status=='published').count()

        else:
            users = []

        if len(users) == 0 and len(posts) == 0:
            flash('No user/post available ', 'danger')
        else:
            flash('Successful Search ', 'info')

        return render_template('search.html', users=users,posts=posts, form=form, db=db, published_posts_count = published_posts_count, query=query, default_value="", timezone=timezone)

    print(f"form validation failed: {form.errors}")
    return render_template('search.html', form=form, default_value="")

# ------------------------------------------------------------------------------
@app.route("/chat", methods=['POST', 'GET'])
def chat():
    username = request.args.get('username')
    user = User.query.filter_by(username=username).first()
    print(user,"User")
    chatform = ChatForm()
    current_name = current_user.username
    current_user_send = User.query.filter_by(username=current_name).first()
    print(current_user_send, "current_user")
    all_chats = Chat.query.filter(or_
        (and_(Chat.sender == current_user_send,Chat.receiver == user),
        and_(Chat.sender == user, Chat.receiver == current_user_send))
    ).order_by(Chat.timestamp)
    print("all chats, before loop")
    for chat in all_chats:
        print(chat.chat_text, chat.sender, chat.receiver)
    if chatform.validate_on_submit():
        print("username successful")
        if user == None:
            flash('User does not exist', 'danger')
            return redirect(url_for('feed'))

        message = chatform.message.data
        current_user_send.send_chat(user, message)
        all_chats = Chat.query.filter(or_
                                      (and_(Chat.sender == current_user_send,Chat.receiver == user),
                                       and_(Chat.sender == user, Chat.receiver == current_user_send))
                                      ).order_by(Chat.timestamp)

    return render_template("chat.html", form=chatform, user=user, all_chats=all_chats, current_user = current_user_send)

@app.route("/all_chats")
def all_chats_with_people():
    user = User.query.filter_by(username=current_user.username).first()
    all_chats = Chat.query.filter(
        (Chat.sender == user) |
        (Chat.receiver == user)
    ).order_by(Chat.timestamp.desc())
    people = []
    chat_text = []
    for chat in all_chats:
        if chat.sender.username != user.username:
            if chat.sender not in people:
                people.append(chat.sender)
                chat_text.append(chat.chat_text)
        else:
            if chat.receiver not in people:
                people.append(chat.receiver)
                chat_text.append(chat.chat_text)
    print(people)
    return render_template("all_chats.html", people = list(zip(people, chat_text)), form=ChatForm())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)

# ------------------------------------------------------------------------------