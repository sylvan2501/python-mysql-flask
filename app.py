from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
import mysql.connector
import os
from dotenv import load_dotenv
from collections import namedtuple
from flask_bcrypt import Bcrypt

load_dotenv()
app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'password'
PASSWORD = os.getenv('PASSWORD')
bcrypt = Bcrypt(app)

# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'
#
#
# @login_manager.user_loader
# def load_user(user):
#     return User.get(user)


mysql_connector = mysql.connector.connect(
    user='root',
    password=PASSWORD,
    host='localhost',
    database='db_example'
)


class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={'placeholder': 'Username'}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={'placeholder': 'Password'}
    )
    submit = SubmitField('Register')

    def validate_account(self, username):
        user_record = namedtuple('UserRecord', ['user_id', 'username', 'password'])
        cursor = mysql_connector.cursor()
        cursor.execute('SELECT * from Users WHERE username = %s', username)
        existing_account = map(user_record._make, cursor.fetchall())
        if existing_account:
            raise ValidationError('The username already exists !')
        cursor.close()


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={'placeholder': 'Username'}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={'placeholder': 'Password'}
    )
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()

    if login_form.validate_on_submit():
        cursor = mysql_connector.cursor()
        cursor.execute('SELECT * FROM Users WHERE username = %s', (login_form.username.data,))
        user_record = cursor.fetchone()
        # print(user_record)
        if user_record:
            if bcrypt.check_password_hash(user_record[2], login_form.password.data):
                # login_user(user_record)
                session['loggedin'] = True
                session['user_id'] = user_record[0]
                session['username'] = user_record[1]
                return redirect(url_for('workspace'))
    return render_template('login.html', form=login_form)


@app.route('/login/logout', methods=['GET', 'POST'])
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/workspace', methods=['GET', 'POST'])
def workspace():
    if 'loggedin' in session:
        return render_template('workspace.html')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(register_form.password.data)
        username = register_form.username.data
        cursor = mysql_connector.cursor()
        input_values = (username, hashed_password)
        dml_operation = 'INSERT INTO Users (username, password) VALUES(%s, %s)'
        cursor.execute(dml_operation, input_values)
        mysql_connector.commit()
        cursor.close()
        return redirect(url_for('login'))
    return render_template('register.html', form=register_form)


@app.route('/', methods=['GET', 'POST'])
def landing_page():
    return render_template('landing_page.html')


@app.route('/add_info', methods=['GET', 'POST'])
def add_info():
    if 'loggedin' in session:
        if request.method == 'POST':
            # fetch the data from user inputs
            pet_details = request.form
            pet_name = pet_details['pet_name']
            owner_name = pet_details['owner_name']
            email = pet_details['email']
            species = pet_details['species']
            sex = pet_details['sex']
            birth = pet_details['birth']
            # create connection to mySQL
            cursor = mysql_connector.cursor()
            input_values = (pet_name, owner_name, email, species, sex, birth)
            dml_operation = 'INSERT INTO Pets (name, owner, email, species, sex, birth) VALUES(%s, %s, %s, %s, %s, %s)'
            cursor.execute(dml_operation, input_values)
            mysql_connector.commit()
            cursor.close()
            return redirect('/display')
    else:
        return redirect('/login')
    return render_template('add_info.html')


@app.route('/edit/<int:pet_id>', methods=['GET', 'POST'])
def edit_info(pet_id):
    if 'loggedin' in session:
        PetRecord = namedtuple('PetRecord', ['pet_id', 'name', 'owner', 'email', 'species', 'sex'])
        cursor = mysql_connector.cursor()
        cursor.execute('SELECT * FROM Pets WHERE pet_id = %s', (pet_id,))
        record = cursor.fetchone()
        pet_record = PetRecord(record[0], record[1], record[2], record[3], record[4], record[5])
        # cursor.close()
        # print(pet_record)
        if request.method == 'POST':
            if pet_record:
                pet_details = request.form
                print(pet_details)
                pet_name = pet_details['pet_name']
                print(pet_name)
                owner_name = pet_details['owner_name']
                email = pet_details['email']
                species = pet_details['species']
                sex = pet_details['sex']
                cursor = mysql_connector.cursor()
                update_fields_values = (pet_name, owner_name, email, species, sex, pet_id)
                dml_operation = 'UPDATE Pets SET name = %s,owner = %s,email = %s,species = %s,sex = %s WHERE pet_id = ' \
                                '%s'
                cursor.execute(dml_operation, update_fields_values)
                mysql_connector.commit()
                cursor.close()
                return redirect('/display')
        return render_template('edit_info.html', petRecord=pet_record)
    else:
        return redirect('/login')


@app.route('/display')
def display():
    if 'loggedin' in session:
        pet_record = namedtuple('PetRecord', ['pet_id', 'name', 'owner', 'email', 'species', 'sex', 'birth'])
        cursor = mysql_connector.cursor()
        cursor.execute('select * from Pets')
        pet_list = map(pet_record._make, cursor.fetchall())
        cursor.close()
        if pet_list:
            return render_template('display.html', petList=pet_list)
        else:
            return 'Data not found !!'
    else:
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
