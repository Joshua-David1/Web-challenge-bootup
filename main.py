from flask import Flask, flash, redirect, url_for, render_template, request, session, g, jsonify, send_from_directory, Response, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, InputRequired, Regexp, EqualTo
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import pyperclip
import os
import urllib.parse
import psycopg2
from os import environ
from decouple import config




app = Flask(__name__)
app.config['SECRET_KEY'] = config("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = config("SQLALCHEMY_DATABASE_URI","sqlite:///user-data-collections.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = "OFF"
db = SQLAlchemy(app)



login_manager = LoginManager()
login_manager.init_app(app)


redirect_url = 'user_home'
global_username = None
current_tab = "available-users"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##DATABASE MODELS

##USER TABLE
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable = False)
    password = db.Column(db.String(25), nullable=False)


##MESSAGES TABLE
class Message(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable = False)
    user_message = db.Column(db.String(10000), nullable = False)

with app.app_context():
	db.create_all()
                    ###########################


def min_char_check(form, field):
    if len(field.data) < 5:
        raise ValidationError('Minimum 5 characters required')


class Same_user_check(object):
    def __init__(self):
        self.error_message = "You cannot send message to yourself"

    def __call__(self, form, field):
        entered_username = field.data
        current_username = current_user.username
        print(current_username)
        print(entered_username)
        if entered_username == current_username:
            raise ValidationError(self.error_message)


same_user_check = Same_user_check

class User_check(object):
    def __init__(self, register = False):
        self.register = register
        self.login_message = "user unavailable"
        self.register_message = "user already exists"

    def __call__(self, form, field):
        if self.register:
            user = User.query.filter_by(username = field.data).first()
            if user:
                raise ValidationError(self.register_message)
        else:
            user = User.query.filter_by(username = field.data).first()
            if user == None:
                    raise ValidationError(self.login_message)


class User_check_admin(object):
    def __init__(self, register = False):
        self.register = register
        self.login_message = "user unavailable"
        self.register_message = "user already exists"

    def __call__(self, form, field):
        if self.register:
            user = User.query.filter_by(username = field.data).first()
            if user.username == "admin":
                raise ValidationError(self.register_message)
        else:
            user = User.query.filter_by(username = field.data).first()
            if user == None:
                    raise ValidationError(self.login_message)
            if user.username != "admin":
            		raise ValidationError(f"[+]{user.username} ain't an admin!")

user_check = User_check
user_check_admin = User_check_admin

class Pass_check(object):
    def __init__(self):
        self.error_message = "Incorrect Password"

    def __call__(self, form, field):
        user = User.query.filter_by(username = form.username.data).first()
        if user is None or field.data != user.password:
            raise ValidationError('Password Incorrect')
                    

pass_check = Pass_check

##Forms##


class LoginFormAdmin(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username","maxlength":25},validators=[InputRequired(message="Enter username"),  user_check_admin()])
    password = PasswordField('password',render_kw={"placeholder":"Password","maxlength":20},validators=[InputRequired(message="Please enter password"),min_char_check,pass_check()])

class LoginForm(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username","maxlength":25},validators=[InputRequired(message="Enter username"),  user_check()])
    password = PasswordField('password',render_kw={"placeholder":"Password","maxlength":20},validators=[InputRequired(message="Please enter password"),min_char_check,pass_check()])


class RegisterForm(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username","maxlength":25},validators=[InputRequired(message="Enter username"), min_char_check,user_check(register = True), Regexp("^[\w]*$", message="Only letter, numbers and underscore."),Regexp("^[a-z\_0-9]*$", message="Only small letters"), Regexp("^[a-z\_]+[a-z\_0-9]*$", message="Cannot begin with numbers") ])
    password = PasswordField('password',render_kw={"placeholder":"Password","maxlength":20},validators=[InputRequired(message="Enter password"),min_char_check])


class SendMsgForm(FlaskForm):
    username = StringField('username', render_kw={"placeholder":"Username to send msg","maxlength":25},validators=[InputRequired(message="Enter username"), user_check(), same_user_check()])
    sent_msg = TextAreaField('sent_msg', render_kw={"placeholder":"type your message here...","maxlength":350},validators=[InputRequired()])


class ChangeUsernameForm(FlaskForm):
    new_username = StringField('new_username', render_kw={"placeholder":"New username", "maxlength" :25}, validators=[InputRequired(message="Enter new username"), min_char_check,user_check(register=True),  Regexp("^[\w]*$", message="Only letter, numbers and underscore."),Regexp("^[a-z\_0-9]*$", message="Only small letters"), Regexp("^[a-z\_]+[a-z\_0-9]*$", message="Cannot begin with numbers") ])

class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('new_password', render_kw={"placeholder":"Enter new password","maxlength":20}, validators = [InputRequired(message="Enter new password"), min_char_check, EqualTo('confirm_password', message="Passwords must match")])
    confirm_password = PasswordField('confirm_password', render_kw={"placeholder":"Re-type password"})
##########

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=10)
    session.modified = True
    g.user = current_user


@app.route("/")
def home():
    if current_user.is_authenticated:
    	print('yes')
    	return redirect(url_for(redirect_url))
    return render_template('index.html')



@app.route("/user_home")
def user_home():
	global redirect_url
	if current_user.is_authenticated:
		redirect_url = 'user_home'
		username = User.query.filter_by(username = current_user.username).first()
		user_messages = Message.query.filter_by(username = current_user.username).all()
		return render_template('user_home.html')
	else:
		return redirect(url_for('home'))

# @app.route('/about')
# def about_page():
#     return render_template('about.html')

@app.route("/user_web_login",methods=["POST", "GET"])
def login_page():
    global redirect_url
    if not current_user.is_authenticated:
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            login_user(user)
            return redirect(url_for('user_home'))
        return render_template('login.html', form=form)
    return redirect(url_for('home'))



@app.route("/admin_home_home_admin")
def admin_home():
	global redirect_url
	if current_user.is_authenticated:
		redirect_url = 'admin_home'
		username = User.query.filter_by(username = current_user.username).first()
		user_messages = Message.query.filter_by(username = current_user.username).all()
		resp = make_response(render_template('admin_page.html'),200)
		resp.headers['Flag-5'] = "WR}YgDEjcNFqP58DQQVa"
		resp.headers['helper'] = "aGVscGVyX2ZpbGUudHh0"
		return resp
	else:
		return redirect(url_for('home'))


@app.route("/helper_file.txt")
def helper_file_page():
	return send_from_directory("static","helper_file.txt")

@app.route("/k3y_is_n0tkn0wn.png")
def stego_file_page():
	return send_from_directory("static","k3y_is_n0tkn0wn.png")


@app.route("/admin_login", methods = ["POST","GET"])
def admin_page():
    global redirect_url
    if not current_user.is_authenticated:
        form = LoginFormAdmin()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            login_user(user)
            return redirect(url_for('admin_home'))
        return render_template('admin-login.html', form=form)
    return redirect(url_for('home'))

#################


# @app.route("/register", methods=["POST", "GET"])
# def register_page():
#     global redirect_url
#     if not current_user.is_authenticated:
#         form = RegisterForm()
#         if form.validate_on_submit():
#             username = form.username.data
#             password = form.password.data
#             # password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=1)
#             new_user = User(username = username, password = password)
#             db.session.add(new_user)
#             db.session.commit()
#             login_user(new_user)
#             return redirect(url_for(redirect_url))
#         return render_template('register.html', form=form)
#     return redirect(url_for(redirect_url))


##### logout page ######
@app.route('/logout',methods=["POST","GET"])
def logout_page():
    global global_username
    global redirect_url
    global current_tab
    if current_user.is_authenticated:
    	print("yes")
    	if request.method == "POST":
    		global_username = None
    		redirect_url = 'messages_page'
    		logout_user()
    		current_tab = "available-users"
    		return redirect(url_for('login_page'))
    	return redirect(url_for('home'))
    return redirect(url_for('home'))

####### delete page ################
# @app.route('/delete', methods=["POST","GET"])
# def delete_page():
#     global global_username
#     global redirect_url
#     global current_tab
#     if current_user.is_authenticated:
#         if request.method == "POST":
#             temp_user = current_user.username
#             global_username = None
#             redirect_url = 'messages_page'
#             current_tab = "available-users"
#             user_msgs_list = Message.query.filter_by(username=temp_user).all()
#             for user in user_msgs_list:
#                 db.session.delete(user)
#                 db.session.commit()
#             user = User.query.filter_by(username=temp_user).first()
#             db.session.delete(user)
#             db.session.commit()
#             flash('Deleted your account...')
#             logout_user()
#             return redirect(url_for('login_page'))
#         return redirect(url_for('home'))
#     return redirect(url_for('home'))


@app.route("/usernames_list")
def usernames_page():
    users_list = []
    users = User.query.all()
    for user in users:
        users_list.append(user.username)
    return jsonify({"Users":users_list})

if __name__ == "__main__":
    port = config("PORT",5000)
    # db.create_all()
    app.run(debug=True, port=port)
