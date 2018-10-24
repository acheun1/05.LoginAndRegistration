#Assignment: Login and Registration
#2018 10 11
#Cheung Anthony

# Validations and Fields to Include
# 1. First Name - letters only, at least 2 characters and that it was submitted

# 2. Last Name - letters only, at least 2 characters and that it was submitted

# 3. Email - valid Email format, does not already exist in the database, and that it was submitted

# 4. Password - at least 8 characters, and that it was submitted

# 5. Password Confirmation - matches password

# Login
# When the user initially registers we would log them in automatically, but the process of "logging in" is simply just verifying that the email and password the user is providing matches up with one of the records that we have in our database table for users.

from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
from mysqlconnection import connectToMySQL

app = Flask(__name__)
bcrypt=Bcrypt(app)
app.secret_key='as43df46asd3f4as4'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    errors = []
    if len(request.form['q0']) < 2:
        errors.append('First name must be at least 2 characters')
    if len(request.form['q1']) < 2:
        errors.append('Last name must be at least 2 characters')    
    q2_str=str(request.form['q2'])        
    q3_str=str(request.form['q3'])
    q3_len=len(request.form['q3'])
    q4_str=str(request.form['q4'])        
    mysql = connectToMySQL('login_registration')
    check_query = "SELECT email FROM register where email=%(email_chk)s;"
    record = {
            'email_chk':request.form['q2']
            }
    check=mysql.query_db(check_query, record)
    if check:
        cnt=1
    else:
        cnt=0
    print(check)
    print(cnt)
    if not q2_str.strip():
        errors.append("Please provide email to complete registration")
    elif q2_str.strip() and not EMAIL_REGEX.match(request.form['q2']):
        errors.append("Please provide a valid email to complete registration")
    elif cnt==1:
        errors.append("This email is already taken!")
    if not q3_str.strip():
        errors.append("Please provide a password to complete registration")
    elif not q3_str.strip() and q3_len<8:
        errors.append("The password must be 8 characters to complete registration")
    if not q4_str.strip() :
        errors.append("Please provide a confirmation password to complete registration")
    if q3_str.strip() and q4_str.strip() and q3_str != q4_str:
        errors.append("Password and confirmation password do not match. Please to complete registration")
        
    if len(errors) > 0:
        for error in errors:
            flash(error)
    
        return redirect("/")

    else:
        hash_pw=bcrypt.generate_password_hash(request.form['password'])
        mysql = connectToMySQL('login_registration')
        insert_query="INSERT INTO register (name_first, name_last, email, password, created_at, update_at) VALUES (%(name_first)s,%(name_last)s,%(email)s,%(password)s  NOW(), NOW());"
        record = {
                'name_first':request.form['q0'],
                'name_last':request.form['q1'],
                'email':request.form['q2'],
                'password':hash_pw 
            }
        new_record_id=mysql.query_db(insert_query, record)
        session['email'] = new_record_id
        mysql = connectToMySQL('login_registration')

    return redirect ('/home')
    # return render_template('submitted.html',email_front=all_email)

@app.route('/login', methods=['POST'])
def login():
    check_query = "SELECT email FROM register where email=%(email_chk)s;"
    record = {
            'email_chk':request.form['q2']
            }
    mysql = connectToMySQL('login_registration')            
    matching_email=mysql.query_db(check_query, record)

    if len(matching_email) ==0:
        flash('Email or password incorrect')
        return redirect ('/')
    else:
        email = matching_email[0]
        if bcrypt.check_password_hash(email['pw_hash'],request.form['q5']):
            session['email_id']=email['id']
            return redirect ('/home')            
        else:
            flash('Email or password incorrect')
            return redirect ('/')

@app.route('/home')
def home():
    if 'email_id' not in session: 
        return redirect('/')
    return render_template('home.html')
    
if __name__=="__main__":
    app.run(debug=True)
