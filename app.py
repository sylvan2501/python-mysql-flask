from flask import Flask, render_template, request, redirect
import mysql.connector
import os
from dotenv import load_dotenv
from collections import namedtuple

load_dotenv()
app = Flask(__name__, static_folder='static')
PASSWORD = os.getenv('PASSWORD')
mysql_connector = mysql.connector.connect(
    user='root',
    password=PASSWORD,
    host='localhost',
    database='db_example'
)


@app.route('/', methods=['GET', 'POST'])
def add_info():
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
        dml_operation = 'INSERT INTO Pets (name, owner, email, species, sex, birth) VALUES(%s, %s, %s, %s, %s,%s)'
        cursor.execute(dml_operation, input_values)
        mysql_connector.commit()
        cursor.close()
        return redirect('/display')
    return render_template('add_info.html')


@app.route('/display')
def display():
    pet_record = namedtuple('PetRecord', ['name', 'pet_id', 'owner', 'email', 'species', 'sex', 'birth'])
    cursor = mysql_connector.cursor()
    query_res = cursor.execute('select * from Pets')
    pet_list = map(pet_record._make, cursor.fetchall())
    if pet_list:
        return render_template('display.html', petList=pet_list)
    else:
        return 'Data not found !!'


if __name__ == '__main__':
    app.run(debug=True)
