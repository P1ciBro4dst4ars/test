from flask import Flask, render_template, redirect, url_for, session, flash, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
from cryptography.fernet import Fernet
import os
import re  

app = Flask(__name__)

# Konfigurasi database
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  
app.config['MYSQL_DB'] = 'pbl_rks'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)

# Fungsi untuk memvalidasi username
def validate_username(username):
    if re.search(r"[\'\"-]", username):  # Melarang simbol ' " -
        raise ValidationError("Username cannot contain ' \" or -")

# Fungsi untuk memvalidasi password
def validate_password(password):
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[0-9]", password):  # Memastikan ada angka
        raise ValidationError("Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Memastikan ada simbol
        raise ValidationError("Password must contain at least one special character.")

# Fungsi untuk memvalidasi email
def validate_email(email):
    if re.search(r"[\'\"-]", email):  # Melarang simbol ' " -
        raise ValidationError("Email cannot contain ' \" or -")

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_name(self, field):
        validate_username(field.data)  # Validasi username

    def validate_password(self, field):
        validate_password(field.data)  # Validasi password

    def validate_email(self, field):
        validate_email(field.data)  # Validasi email
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class FileForm(FlaskForm):
    file = FileField("File", validators=[DataRequired()])
    key = StringField("Encryption Key", validators=[DataRequired()])  
    submit = SubmitField("Upload")

class DecryptForm(FlaskForm):
    file_name = SelectField("Select file to decrypt", choices=[], validators=[DataRequired()])
    key = StringField("Decryption Key", validators=[DataRequired()])
    submit = SubmitField("Decrypt")

class TextForm(FlaskForm):
    text = StringField("Text to Encrypt/Decrypt", validators=[DataRequired()])
    key = StringField("Encryption Key", validators=[DataRequired()])
    action = SelectField("Action", choices=[('encrypt', 'Encrypt'), ('decrypt', 'Decrypt')], validators=[DataRequired()])
    submit = SubmitField("Process")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]  # Simpan ID pengguna dalam sesi
            flash("Login successful!")
            return redirect(url_for('dashboard'))  # Arahkan ke dashboard
        else:
            flash("Login failed. Please check your email and password.")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        file_form = FileForm()
        decrypt_form = DecryptForm()
        text_form = TextForm()

        # List uploaded files
        uploaded_files = os.listdir('uploads')
        decrypt_form.file_name.choices = [(file, file) for file in uploaded_files if not file.endswith('.key')]

        decrypted_file_path = None  # Variable to store decrypted file path
        processed_text = None  # Variable to store processed text

        if file_form.validate_on_submit():
            file = file_form.file.data
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)

            # Ambil kunci dari form
            key = file_form.key.data.encode()  # Menggunakan kunci dari form
            try:
                encrypt_file(file_path, key)

                # Simpan kunci ke file terpisah
                key_file_path = os.path.join('uploads', f"{file.filename}.key")
                with open(key_file_path, 'wb') as key_file:
                    key_file.write(key)

                flash(f"File '{file.filename}' has been encrypted.")
            except Exception as e:
                flash(f"Encryption failed: {str(e)}")
            return redirect(url_for('dashboard'))

        if decrypt_form.validate_on_submit():
            file_name = decrypt_form.file_name.data
            file_path = os.path.join('uploads', file_name)

            # Get the key from the form
            key = decrypt_form.key.data.encode()  # Convert key to bytes
            try:
                decrypted_file_path = decrypt_file(file_path, key)
                flash(f"File '{file_name}' has been decrypted.")
            except Exception as e:
                flash(f"Decryption failed: {str(e)}")

        return render_template('dashboard.html', user=user, file_form=file_form, decrypt_form=decrypt_form, text_form=text_form, uploaded_files=uploaded_files, decrypted_file_path=decrypted_file_path, processed_text=processed_text)
    return redirect(url_for('login'))

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        return send_from_directory('uploads', filename, as_attachment=True)
    except FileNotFoundError:
        flash("File not found!")
        return redirect(url_for('dashboard'))

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    try:
        os.remove(os.path.join('uploads', filename))
        flash(f"File '{filename}' has been deleted.")
    except Exception as e:
        flash(f"Error deleting file: {str(e)}")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
        decrypted = fernet.decrypt(encrypted)
    
    decrypted_file_path = file_path.replace('.encrypted', '_decrypted') 
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)
    
    return os.path.basename(decrypted_file_path) 


if __name__ == '__main__':
    # Pastikan folder 'uploads' ada
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)