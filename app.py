from flask import Flask, render_template, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired,DataRequired, Length, EqualTo
import os
from datetime import datetime
from sqlalchemy import exc
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user

basedir = os.path.abspath(os.path.dirname(__file__))

app =  Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'I am secret'

bcrypt = Bcrypt(app)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
     # since the user_id is just the primary key of our user table, use it in the query for the user
     return User.query.get(int(user_id))

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True),default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.firstname, self.email, self.lastname}>'



class registerForm(FlaskForm):
    firstname = StringField('Enter firstname', validators=[DataRequired()] )
    lastname = StringField('Enter lastname', validators=[DataRequired()] )
    email = StringField('Enter email', validators=[DataRequired()] )
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=25)])
    confirm = PasswordField( "Repeat password",validators=[DataRequired(), EqualTo("password", message="Passwords must match."),], )
    submit = SubmitField("Register")

class loginForm(FlaskForm):
    email = StringField('Enter email', validators=[DataRequired()] )
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=25)])
    submit = SubmitField("Login")



@app.route('/')
@login_required
def home():
    # autenticate page
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login(): 
    form = loginForm()  
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user is None:
           flash("Email address not found in our system", "danger")
           return render_template('login.html', form=form) 
       
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("You are now logged in successfully.", "success")
            return redirect('/')
        else:
            flash("Invalid credential please try again", "danger")
            return render_template('login.html', form=form)  
   
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])
def register():
    form = registerForm()
    if form.validate_on_submit():
          try:
             user = User(firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        email=form.email.data,
                        password= bcrypt.generate_password_hash(form.password.data))
             db.session.add(user)
             db.session.commit()   
             flash("Account created Successfully,You can now login with your username and password!", "success") 
             return redirect('login') 
          except exc.IntegrityError as e:
              flash("Email not registerddbdb", "error") 
          except exc.OperationalError as e:
               flash('An Error occured', "error")   
    return render_template('register.html', form=form)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect('login')

@app.errorhandler(405)
def method_not_allowed(e):
     return render_template('405.html', e=e)

@app.errorhandler(404)
def page_not_found(e):
     return render_template('404.html', e=e)

@app.errorhandler(500)
def internal_server_error(e):
     return render_template('500.html', e=e)