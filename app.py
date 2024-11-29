from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mrlssrbkhp'
app.config['MYSQL_DB'] = 'nas_db'
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Initialize MySQL
mysql = MySQL(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password, role, permissions):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.permissions = permissions

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        # Check if user already exists
        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Username already exists!', 'danger')
        else:
            # Create new user
            cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (username, password, role))
            conn.commit()
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

# Load user function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if user:
        return User(user[0], user[1], user[2], user[3], user[4])
    return None

# Home Route
@app.route('/')
@login_required
def index():
    # Fetch files uploaded by the logged-in user
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE user_id = %s", (current_user.id,))
    files = cursor.fetchall()
    return render_template('index.html', files=files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin'))  # Redirect to admin page if admin
        else:
            return redirect(url_for('index'))  # Redirect to index page for non-admin users
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve user from the database
        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user:  # Check if user exists
            stored_password = user[2]  # Assuming the password is in the 3rd column (index 2)
            
            # Compare plain text passwords
            if stored_password == password:
                user_obj = User(user[0], user[1], user[2], user[3], user[4])  # Including permissions
                login_user(user_obj)
                flash('Login successful!', 'success')  # Optional: Add a flash message
                
                # Redirect based on user role
                if user[3] == 'admin':
                    return redirect(url_for('admin'))  # Redirect to admin page if role is admin
                else:
                    return redirect(url_for('index'))  # Redirect to index page for non-admin users
            
            else:
                flash('Invalid login credentials!', 'danger')
        else:
            flash('Invalid login credentials!', 'danger')
    
    return render_template('login.html')

# Admin Route
@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        return redirect(url_for('index'))  # Redirect to index if not an admin
    
    # Fetch all users
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    return render_template('admin.html', users=users)

# Create User Route (Admin Only)
@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        return redirect(url_for('index'))  # Redirect to index if not an admin
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        # Check if user already exists
        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Username already exists!', 'danger')
        else:
            # Create new user
            cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (username, password, role))
            conn.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('admin'))  # Redirect back to admin page
    
    return render_template('create_user.html')

# Delete User Route (Admin Only)
@app.route('/delete_user/<int:user_id>', methods=['GET'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))  # Redirect to index if not an admin
    
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin'))  # Redirect to admin page

#modify user
@app.route('/modify_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def modify_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))  # Redirect to index if not an admin
    
    conn = mysql.connection
    cursor = conn.cursor()
    
    # Fetch user details for the given user_id
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('admin'))  # Redirect back to admin page if the user does not exist

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        permissions = request.form['permissions']
        
        # You can also add validation for empty fields or passwords
        if username and password and role and permissions:
            # Update the user in the database
            cursor.execute("""
                UPDATE users 
                SET username = %s, password = %s, role = %s, permissions = %s 
                WHERE id = %s
            """, (username, password, role, permissions, user_id))
            conn.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('admin'))  # Redirect back to admin page after modification
        else:
            flash('All fields are required!', 'danger')

    # Pass the current user details to the template
    return render_template('modify_user.html', user=user)

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# File Upload Route
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Save the file
            file.save(file_path)
            
            # Store file metadata in the database
            conn = mysql.connection
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO files (user_id, filename, filepath) VALUES (%s, %s, %s)",
                (current_user.id, filename, file_path)
            )
            conn.commit()
            
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('index'))  # Redirect to the home page after uploading
        
        else:
            flash('Invalid file type!', 'danger')
    
    return render_template('upload.html')

# Check if file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/delete_file/<int:file_id>', methods=['GET'])
@login_required
def delete_file(file_id):
    # Fetch the file record from the database
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, current_user.id))
    file = cursor.fetchone()

    if file:
        file_path = file[3]  # Assuming file[3] is the file path in the database
        
        # Delete the file from the filesystem
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Remove the file record from the database
        cursor.execute("DELETE FROM files WHERE id = %s", (file_id,))
        conn.commit()
        flash('File deleted successfully!', 'success')
    else:
        flash('File not found!', 'danger')
    
    return redirect(url_for('index'))

from flask import send_from_directory, flash, redirect, url_for
import os

@app.route('/download_file/<int:file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    # Fetch the file record from the database
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE id = %s AND user_id = %s", (file_id, current_user.id))
    file = cursor.fetchone()

    if file:
        # Assuming file[3] is the relative file path stored in the database
        file_path = file[3]  # File path stored in the database (e.g., 'uploads/filename.ext')
        
        # Check if the file exists
        if os.path.exists(file_path):
            directory = os.path.dirname(file_path)  # Get the directory path from file_path
            filename = os.path.basename(file_path)  # Get the filename from the file_path
            
            try:
                # Pass directory and filename directly to send_from_directory
                return send_from_directory(directory, filename, as_attachment=True)
            except FileNotFoundError:
                flash('File not found on the server!', 'danger')
                return redirect(url_for('index'))
        else:
            flash('File not found on the server!', 'danger')
            return redirect(url_for('index'))
    else:
        flash('File not found in the database!', 'danger')
        return redirect(url_for('index'))

#system monitor
import psutil
from flask import Flask, render_template

# Add this route for system monitoring
@app.route('/system_monitoring')
@login_required
def system_monitoring():
    # Get system stats
    disk_usage = psutil.disk_usage('/')
    cpu_usage = psutil.cpu_percent(interval=1)  # Get CPU usage as a percentage
    system_logs = get_system_logs()

    return render_template('monitor.html', disk_usage=disk_usage, cpu_usage=cpu_usage, system_logs=system_logs)

def get_system_logs():
    """
    Fetch the system logs. This is just an example of reading system logs on a Linux machine.
    Modify it according to your OS and requirements.
    """
    logs = []
    try:
        with open('/var/log/syslog', 'r') as f:  # Path to system log (for Linux systems)
            logs = f.readlines()[-10:]  # Get the last 10 log entries
    except Exception as e:
        logs = [f"Error reading system logs: {str(e)}"]
    return logs


if __name__ == '__main__':
    app.run(debug=True)

