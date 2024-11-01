from flask import Flask, request, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from wtforms.validators import ValidationError
import requests
import re
import os
import hashlib          
import difflib

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'upb'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela

    TODO: tabulku je treba doimplementovat
'''
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(64), unique=False, nullable=False)
    salt = db.Column(db.LargeBinary(16), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
#Odkomentuj, ak chcete vytvorit tabulku a uzivatela
with app.app_context():
    db.create_all()
    
#    test_user = User(username='test', password='test')
#    db.session.add(test_user)
#    db.session.commit()

#funkcie
def password_complexity_check(form, field):
    password = field.data
    if (len(password) < 10 or 
        not re.search(r"[A-Z]", password) or 
        not re.search(r"[a-z]", password) or 
        not re.search(r"[0-9]", password) or 
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        raise ValidationError('Heslo musí obsahovať aspoň 10 znakov, jedno veľké písmeno, jedno malé písmeno, jedno číslo a jeden špeciálny znak.')

def generate_salt():
    return os.urandom(16)

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def is_common_password(password):
    try:
        with open('10k-most-common-passwords.txt', 'r') as file:
            common_passwords = file.read().splitlines()
        return password in common_passwords
    except FileNotFoundError:
        print("Súbor so zoznamom bežných hesiel sa nenašiel.")
        return False
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), password_complexity_check])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_password(self, field):
        password = field.data
        username = self.username.data
        
        # Kontrola, či je heslo podobné používateľskému menu (napr. 70 % a viac podobnosti)
        similarity = difflib.SequenceMatcher(None, username.lower(), password.lower()).ratio()

        if similarity > 0.7:  
            raise ValidationError('Heslo je príliš podobné používateľskému menu. Zvoľte si odlišnejšie heslo.')
        
        # Kontrola, či heslo nie je moc podobne s bežnými heslami
        with open('10k-most-common-passwords.txt', 'r') as file:
                    common_passwords = file.read().splitlines()
                    
        for common_password in common_passwords:
            similarity = difflib.SequenceMatcher(None, common_password, password).ratio()
            if similarity > 0.7:
                raise ValidationError('Heslo je príliš podobné bežnému heslu. Zvoľte si odlišnejšie heslo.')

        # Kontrola, či heslo nie je medzi bežnými heslami
        if is_common_password(password):
            raise ValidationError('Heslo je príliš bežné. Zvoľte si silnejšie heslo.')


@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdwCmcqAAAAAAYaHnmrGy-MlyToQY_dxgDJS3MB'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdwCmcqAAAAAGftjX7zQ1OyH2-w7Lo0KqKc9Fj6'

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        recaptcha_response = request.form['g-recaptcha-response']
        secret_key = "6LdwCmcqAAAAAGftjX7zQ1OyH2-w7Lo0KqKc9Fj6"
        payload = {
            'secret': secret_key,
            'response': recaptcha_response
        }

        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
        result = response.json()

        if result['success']:
            # Pokračuje overenie prihlasovacích údajov

            user = User.query.filter_by(username=form.username.data).first()
            if user:
                hashed_input_password = hash_password(form.password.data, user.salt)
                if hashed_input_password == user.password:
                    login_user(user)
                    return redirect(url_for('home'))

            flash('Nesprávne prihlasovacie údaje. Skontrolujte, či je používateľské meno a heslo správne.', 'error')
        else:
            flash('Overenie reCAPTCHA zlyhalo. Skúste to znova.', 'error')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])        
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        
        new_user = User(username=username, password=hashed_password, salt=salt)
        db.session.add(new_user)
        db.session.commit()

        print(f'Nový používateľ zaregistrovaný: {username}')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@login_required
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=1337)
