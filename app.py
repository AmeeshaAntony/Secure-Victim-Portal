import datetime
from flask import Flask, make_response, render_template, request, redirect, url_for, flash, session , jsonify 
import sqlite3
import os
from datetime import datetime
import re
from flask_bcrypt import Bcrypt
from psutil import users
from werkzeug.utils import secure_filename
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "your_secret_key"  # Required for flash messages
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/users.db'
SECRET_KEY = "crime"  # Set the correct decryption key
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

db = SQLAlchemy(app)

def get_case(case_number):
    """Fetch case details from the database using case number."""
    conn = sqlite3.connect("cases.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases WHERE case_number = ?", (case_number,))
    case = cursor.fetchone()
    conn.close()
    return case

UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize `police.db` for police officer management
def init_police_db():
    with sqlite3.connect('police.db') as conn:
        cursor = conn.cursor()

        # Start a transaction
        cursor.execute("BEGIN")

        try:
            # Create the police_officer table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS police_officer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    phone TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    state TEXT NOT NULL,
                    district TEXT NOT NULL,
                    position TEXT NOT NULL,
                    police_id TEXT UNIQUE,
                    aadhar_card_path TEXT
                )
            ''')

            # Check if columns exist before adding them
            cursor.execute("PRAGMA table_info(police_officer)")
            columns = [column[1] for column in cursor.fetchall()]  # Get column names

            if 'police_id' not in columns:
                cursor.execute("ALTER TABLE police_officer ADD COLUMN police_id TEXT UNIQUE")

            if 'aadhar_card_path' not in columns:
                cursor.execute("ALTER TABLE police_officer ADD COLUMN aadhar_card_path TEXT")

            # Create the query table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS query (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Commit the transaction
            conn.commit()
        except sqlite3.Error as e:
            # Rollback the transaction in case of an error
            conn.rollback()
            print(f"An error occurred: {e}")
        # No need to close the connection explicitly; the 'with' statement handles it

# Call the function to apply changes
init_police_db()

# Create the database and users table if not exists


conn = sqlite3.connect('admin.db')
cursor = conn.cursor()

# Create the admin table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        position TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        state TEXT NOT NULL,
        district TEXT NOT NULL,
        judicial_id TEXT UNIQUE NOT NULL,
        id_card_photo TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')

conn.commit()
conn.close()
def init_admin_db():
    with sqlite3.connect('admin.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                position TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                state TEXT NOT NULL,
                district TEXT NOT NULL,
                judicial_id TEXT UNIQUE NOT NULL,
                id_card_photo TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()
# Call the function to ensure the database is set up
init_admin_db()

# Initialize `cases.db` for case management
def init_cases_db():
    with sqlite3.connect('cases.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT NOT NULL UNIQUE,
                date_of_reporting TEXT NOT NULL,
                place TEXT NOT NULL,
                reported_person TEXT NOT NULL,
                phone_number TEXT NOT NULL,
                time TEXT NOT NULL,
                photo TEXT
            )
        ''')
        conn.commit()

# Initialize `case_description.db` for case questioning
def init_case_description_db():
    with sqlite3.connect('case_description.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS case_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT NOT NULL,
                detailed_description TEXT NOT NULL,
                suspected_person TEXT NOT NULL,
                visited_location TEXT NOT NULL,
                visit_reason TEXT NOT NULL,
                communication_details TEXT,
                evidence_details TEXT
            )
        ''')
        conn.commit()
def add_case_status_column():
    with sqlite3.connect("cases.db") as conn:
        cursor = conn.cursor()
        cursor.execute("ALTER TABLE cases ADD COLUMN case_status TEXT DEFAULT 'Registered'")
        conn.commit()

# Run the function once to add the column if it doesn't exist
try:
    add_case_status_column()
except sqlite3.OperationalError:
    pass 

import sqlite3

# Connect to the database (or create if it doesn't exist)
conn = sqlite3.connect('access_control.db')
cursor = conn.cursor()

# Create table for officers' access levels
cursor.execute('''
    CREATE TABLE IF NOT EXISTS officers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        rank TEXT NOT NULL,
        access_level TEXT NOT NULL CHECK(access_level IN ('Read', 'Write', 'Admin'))
    )
''')

# Create table for case logs
cursor.execute('''
    CREATE TABLE IF NOT EXISTS case_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        officer_id INTEGER,
        case_number TEXT,
        action TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (officer_id) REFERENCES officers(id)
    )
''')


# Insert sample data (only if the table is empty)
cursor.execute("SELECT COUNT(*) FROM officers")
if cursor.fetchone()[0] == 0:
    cursor.executemany('''
        INSERT INTO officers (name, rank, access_level) VALUES (?, ?, ?)
    ''', [
        ("Officer A","Constable","Read"),
        ("Officer B", "Sub Inspector", "Read"),
        ("Officer C", "Inspector", "Read"),
        ("Officer D", "Circle Inspector", "Write"),
        ("Officer E", "Judge", "Admin"),
        ("Officer F", "DGP", "Admin")
    ])

# Commit and close
conn.commit()
conn.close()

print("Database and table created successfully!")

conn = sqlite3.connect('user.db')
cursor = conn.cursor()

# Create the users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    aadhar TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    district TEXT NOT NULL,
    police_station TEXT NOT NULL,
    aadhar_card_filename TEXT NOT NULL
)
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name TEXT NOT NULL,
        feedback TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')

# Commit changes and close the connection
def create_alert_table():
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_alert (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            location TEXT NOT NULL,
            district TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

create_alert_table()
print("✅ user_alert table created successfully!")
# Call functions to initialize databases
init_police_db()
init_cases_db()
init_case_description_db()

@app.route('/')
def welcome():
    return render_template('welcome.html')


@app.route('/police/home')
def police_home():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('police_login'))
    return render_template('home.html', name=session.get('user_name'))

@app.route('/about')
def about():
    return render_template('police_about.html')

@app.route('/police/logout')
def police_logout():
    # Clear the session
    session.clear()
    return redirect(url_for('police_login'))

@app.route('/assign_officers')
def assign_officers():
    with sqlite3.connect("cases.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT case_number, place FROM cases")
        cases = cursor.fetchall()
    
    return render_template("assign_officers.html", cases=cases)


@app.route('/assign_officer/<case_number>')
def assign_specific_officer(case_number):
    with sqlite3.connect("police.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, position FROM police_officer")
        officers = cursor.fetchall()
    
    return render_template("assign_specific_officer.html", case_number=case_number, officers=officers)


@app.route('/police', methods=['GET', 'POST'])
def police_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('police.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, password FROM police_officer WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            user_id, user_name, hashed_password = user
            if check_password_hash(hashed_password, password):
                session['user_id'] = user_id
                session['user_name'] = user_name
                flash("Login successful!", "success")
                return redirect(url_for('police_home'))  
            else:
                flash("Incorrect password. Please try again.", "danger")
        else:
            flash("No account found with this email.", "danger")

    return render_template('police_login.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/police/signup', methods=['GET', 'POST'])
def police_signup():
    if request.method == 'POST':
        name = request.form['name']
        police_id = request.form['police_id']
        phone = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        state = request.form['state']
        district = request.form['district']
        position = request.form['position']
        
        # Check password match
        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
            return redirect(url_for('police_signup'))

        # Validate Police ID
        if not police_id.startswith("P") or not police_id[1:].isdigit():
            flash("Invalid Police ID. It must start with 'P' followed by numbers.", "danger")
            return redirect(url_for('police_signup'))

        # Hash Password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Handle Aadhar Card Upload
        if 'aadhar_card' not in request.files:
            flash("Please upload your Aadhar card.", "danger")
            return redirect(url_for('police_signup'))
        
        aadhar_card = request.files['aadhar_card']
        if aadhar_card.filename == '' or not allowed_file(aadhar_card.filename):
            flash("Invalid file format. Please upload a PNG, JPG, JPEG, or PDF.", "danger")
            return redirect(url_for('police_signup'))
        
        filename = secure_filename(aadhar_card.filename)
        aadhar_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        aadhar_card.save(aadhar_path)

        try:
            with sqlite3.connect('police.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO police_officer (name, police_id, phone, email, password, state, district, position, aadhar_card_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (name, police_id, phone, email, hashed_password, state, district, position, aadhar_path))
                conn.commit()

            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('police_login'))

        except sqlite3.IntegrityError:
            flash("Error: Police ID, Email, or Phone already exists.", "danger")
            return redirect(url_for('police_signup'))

    return render_template('police_signup.html')

### ✅ Route to Register Cases
@app.route('/register_cases', methods=['GET', 'POST'])
def register_case():
    if request.method == 'POST':
        case_number = request.form["case_number"]
        date_of_reporting = request.form["date_of_reporting"]
        place = request.form["place"]
        reported_person = request.form["reported_person"]
        phone_number = request.form["phone_number"]
        time = request.form["time"]
        photo = request.files["photo"]

        photo_filename = None
        if photo and photo.filename:
            photo_filename = photo.filename  # Save only filename
            photo.save(os.path.join(app.config["UPLOAD_FOLDER"], photo_filename))

        try:
            with sqlite3.connect("cases.db") as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO cases (case_number, date_of_reporting, place, reported_person, phone_number, time, photo)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (case_number, date_of_reporting, place, reported_person, phone_number, time, photo_filename))
                conn.commit()

            flash("Case registered successfully!", "success")
            return redirect(url_for("case_questioning", case_number=case_number))
        except sqlite3.IntegrityError:
            flash("Case number already exists!", "danger")

    return render_template("register_cases.html")

@app.route('/case_registered')
def case_registered():
    return render_template("case_registered.html")

@app.route('/settings')
def settings():
    return render_template('settings.html')


@app.route('/case_questioning/<case_number>', methods=['GET', 'POST'])
def case_questioning(case_number):
    if request.method == 'POST':
        detailed_description = request.form.get("detailed_description")
        suspected_person = request.form.get("suspected_person")
        visited_location = request.form.get("visited_location")
        visit_reason = request.form.get("visit_reason")
        communication_details = request.form.get("communication_details")
        evidence_details = request.form.get("evidence_details")

        with sqlite3.connect("case_description.db") as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO case_details (case_number, detailed_description, suspected_person, visited_location, visit_reason, communication_details, evidence_details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (case_number, detailed_description, suspected_person, visited_location, visit_reason, communication_details, evidence_details))
            conn.commit()

        flash("Case details saved successfully!", "success")
        return redirect(url_for("case_registered"))

    return render_template("case_questioning.html", case_number=case_number)

### ✅ Route to View & Manage Cases
@app.route('/manage_cases')
def manage_cases():
    with sqlite3.connect("cases.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, case_number, date_of_reporting, place, reported_person FROM cases")
        cases = cursor.fetchall()

    return render_template('manage_cases.html', cases=cases)

@app.route('/admin/logs')
def admin_logs():
    conn = sqlite3.connect('access_control.db')
    conn.row_factory = sqlite3.Row  # This allows accessing columns by name
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM case_logs ORDER BY timestamp DESC")  # Fetch logs sorted by timestamp
    logs = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin_logs.html', logs=logs)


@app.route('/case_details/<case_number>')
def case_details(case_number):
    officer_id = session.get('officer_id')  # Ensure officer is logged in

    # Fetch case details from your database
    with sqlite3.connect('cases.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE case_number = ?", (case_number,))
        case = cursor.fetchone()

    if not case:
        flash("Case not found!", "danger")
        return redirect(url_for('home'))

    # ✅ Log that the officer viewed the case details
    log_case_action(officer_id, case_number, "Viewed Case Details")

    return render_template('case_details.html', case=case)

def log_case_action(officer_id, case_number, action):
    conn = sqlite3.connect("access_control.db")
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO case_logs (officer_id, case_number, action, timestamp)
        VALUES (?, ?, ?, ?)
    """, (officer_id, case_number, action, datetime.now()))

    conn.commit()
    conn.close()

@app.route('/decrypt_photo/<case_number>', methods=['GET', 'POST'])
def decrypt_photo(case_number):
    case = get_case(case_number)
    officer_id = session.get('officer_id')  # Assuming officer is logged in

    if not case:
        flash("Case not found!", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        entered_key = request.form.get('secret_key')

        if entered_key == SECRET_KEY:
            # ✅ Automatically log that the officer decrypted the photo
            log_case_action(officer_id, case_number, "Decrypted Photo")
            return render_template('decrypt_photo.html', case=case, decrypted=True)
        else:
            flash("Incorrect secret key! Try again.", "danger")
            return redirect(url_for('decrypt_photo', case_number=case_number))

    return render_template('decrypt_photo.html', case=case, decrypted=False)

@app.route('/case_details_view')
def case_details_view():
    with sqlite3.connect("cases.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT case_number, place, time, case_status FROM cases")
        cases = cursor.fetchall()

    # Fetch detailed descriptions from case_description.db
    case_descriptions = {}
    with sqlite3.connect("case_description.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT case_number, detailed_description FROM case_details")
        descriptions = cursor.fetchall()
    
    # Map case descriptions to case numbers
    for case_number, description in descriptions:
        case_descriptions[case_number] = description

    # Merge data from both databases
    case_data = []
    for case in cases:
        case_number, place, time, case_status = case
        detailed_description = case_descriptions.get(case_number, "No Description Available")
        case_data.append((case_number, place, time, detailed_description, case_status))

    return render_template("detail_case.html", cases=case_data)

@app.route('/cases')
def show_cases():
    conn = sqlite3.connect('cases.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases")  # Modify based on your table structure
    cases = cursor.fetchall()
    conn.close()
    return render_template('detail_case.html', cases=cases)

@app.route('/update_case_status', methods=['POST'])
def update_case_status():
    case_number = request.form.get('case_number')
    new_status = request.form.get('new_status')

    conn = sqlite3.connect('cases.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE cases SET status = ? WHERE case_number = ?", (new_status, case_number))
    conn.commit()
    conn.close()

    return jsonify({'success': True})

@app.route('/delete_case', methods=['POST'])
def delete_case():
    try:
        case_number = request.form.get('case_number')
        print(f"Deleting case: {case_number}")  # Debugging log

        conn = sqlite3.connect('cases.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cases WHERE case_number = ?", (case_number,))
        conn.commit()
        conn.close()

        print("Case deleted successfully!")  # Debugging log
        return jsonify({'success': True})
    except Exception as e:
        print("Error deleting case:", str(e))  # Debugging log
        return jsonify({'success': False, 'error': str(e)})

@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('police_login'))

    user_id = session['user_id']
    
    with sqlite3.connect("police.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, phone, email, position, state, district FROM police_officer WHERE id = ?", (user_id,))
        user = cursor.fetchone()

    if not user:
        flash("Profile not found!", "danger")
        return redirect(url_for('settings'))

    return render_template("update_profile.html", user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('police_login'))

    user_id = session['user_id']

    with sqlite3.connect("police.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, phone, email, position, state, district FROM police_officer WHERE id = ?", (user_id,))
        user = cursor.fetchone()

    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        position = request.form['position']
        state = request.form['state']
        district = request.form['district']

        with sqlite3.connect("police.db") as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE police_officer 
                SET name = ?, phone = ?, email = ?, position = ?, state = ?, district = ?
                WHERE id = ?
            ''', (name, phone, email, position, state, district, user_id))
            conn.commit()

        flash("Profile updated successfully!", "success")
        return redirect(url_for('update_profile'))

    return render_template("edit_profile.html", user=user)

@app.route('/police_query')
def police_query():
    return render_template('police_query.html')

@app.route('/police_notification')
def police_notification_settings():
    return render_template('police_notification.html')

def get_db_connection():
    conn = sqlite3.connect('police.db')
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

@app.route('/submit_query', methods=['POST'])
def submit_query():
    # Get form data
    name = request.form.get('name')
    email = request.form.get('email')
    query_type = request.form.get('query-type')
    description = request.form.get('description')

    # Validate form data
    if not name or not email or not query_type or not description:
        flash("All fields are required!", "error")
        return redirect(url_for('police_query'))

    # Insert data into the database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO query (name, email, query_type, description) VALUES (?, ?, ?, ?)",
            (name, email, query_type, description)
        )
        conn.commit()
        flash("Query submitted successfully!", "success")
    except sqlite3.Error as e:
        flash(f"An error occurred: {e}", "error")
    finally:
        conn.close()

    # Redirect back to the query form
    return redirect(url_for('police_query'))

@app.route('/police/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('police_login'))


def check_admin(email, password):
    """
    Checks if the given email and password match an admin in the database.

    :param email: Admin's email
    :param password: Password entered by the admin
    :return: Admin details if valid, None otherwise
    """
    try:
        with sqlite3.connect("admin.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, full_name, password FROM admin WHERE email = ?", (email,))
            admin = cursor.fetchone()

            if admin:
                admin_id, admin_name, hashed_password = admin
                # Verify password using bcrypt
                if bcrypt.check_password_hash(hashed_password, password):
                    return (admin_id, admin_name)  # Return admin details if authentication is successful
    except sqlite3.Error as e:
        print("Database error:", e)

    return None  # Return None if authentication fails

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['username']  # Assuming 'username' is actually 'email'
        password = request.form['password']
        
        admin = check_admin(email, password)  # Function to verify admin credentials
        
        if admin:
            session['admin_id'] = admin[0]  # Store admin ID
            session['admin_name'] = admin[1]  # Store admin Name
            return redirect(url_for('admin_home'))  # Redirect to Admin Dashboard
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for('admin_login'))  # Show flash message only on failure

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html', name=session.get('admin_name'))

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        position = request.form['position']
        phone = request.form['phone']
        email = request.form['email']
        state = request.form['state']
        district = request.form['district']
        judicial_id = request.form['judicial_id']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        id_card_photo = request.files['id_card_photo']

        # ✅ **Validations**
        # Phone number must be exactly 10 digits
        if not re.match(r'^\d{10}$', phone):
            flash("Phone number must be exactly 10 digits", "error")
            return redirect(url_for('admin_signup'))

        # Email validation
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash("Invalid email format", "error")
            return redirect(url_for('admin_signup'))

        # Judicial ID must start with 'J' and end with a digit
        if not re.match(r'^J.*\d$', judicial_id):
            flash("Judicial ID must start with 'J' and end with a digit", "error")
            return redirect(url_for('admin_signup'))

        # Password must have an uppercase, lowercase, digit, special character, and at least 8 characters
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            flash("Password must have uppercase, lowercase, number, special character, and be at least 8 characters long", "error")
            return redirect(url_for('admin_signup'))

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for('admin_signup'))

        # ✅ **Handle Image Upload**
        if id_card_photo.filename == '':
            flash("Please upload an ID card photo", "error")
            return redirect(url_for('admin_signup'))

        filename = secure_filename(id_card_photo.filename)
        id_card_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        id_card_photo.save(id_card_path)  # Save the file

        # ✅ **Store Data in Database**
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash password before storing
        try:
            with sqlite3.connect('admin.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO admin (full_name, position, phone, email, state, district, judicial_id, id_card_photo, password)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (full_name, position, phone, email, state, district, judicial_id, id_card_path, hashed_password))
                conn.commit()
                flash("Admin registered successfully!", "success")
                return redirect(url_for('admin_login'))
        except sqlite3.IntegrityError:
            flash("Email or Judicial ID already exists!", "error")
            return redirect(url_for('admin_signup'))

    return render_template('admin_signup.html')

def no_cache(view):
    """Decorator to prevent caching"""
    def wrapped_view(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return wrapped_view

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/admin_home")
def admin_home():
    if "admin_id" not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for("admin_login"))

    return render_template("admin_home.html", name=session.get("admin_name"))


@app.route('/admin/logout')
def admin_logout():
    session.clear()  # Clear session
    response = redirect(url_for('admin_login'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def get_police_officers():
    conn = sqlite3.connect('police.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, phone, email, state, district, position FROM police_officer")
    officers = cursor.fetchall()
    conn.close()
    
    return [{"id": o[0], "name": o[1], "phone": o[2], "email": o[3], "state": o[4], "district": o[5], "position": o[6]} for o in officers]

@app.route('/get_police_officers')
def fetch_officers():
    return jsonify(get_police_officers())

# Route to render the Local Police Officers page
@app.route('/local_police_officers')
def local_police_officers():
    return render_template('local_police_officer.html')

@app.route('/delete_police_officer/<int:officer_id>', methods=['DELETE'])
def delete_police_officer(officer_id):
    conn = sqlite3.connect('police.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM police_officer WHERE id = ?", (officer_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Officer deleted successfully"}), 200

def get_cases():
    conn = sqlite3.connect('cases.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, case_number, date_of_reporting, place, reported_person, phone_number, time, photo FROM cases")
    cases = cursor.fetchall()
    conn.close()

    return [{"id": c[0], "case_number": c[1], "date_of_reporting": c[2], "place": c[3], 
             "reported_person": c[4], "phone_number": c[5], "time": c[6], "photo": c[7]} for c in cases]

@app.route('/get_cases')
def fetch_cases():
    return jsonify(get_cases())

@app.route('/case_management')
def case_management():
    return render_template('secret_key_prompt.html')

@app.route('/verify_secret_key', methods=['POST'])
def verify_secret_key():
    key = request.form.get('key')
    if key == "crime":
        return render_template('case_details_admin.html')  # Load the admin case details page
    else:
        return "Unauthorized Access", 403
    
def get_officers():
    conn = sqlite3.connect("access_control.db")  # ✅ Correct database
    cur = conn.cursor()
    cur.execute("SELECT id, rank, access_level FROM officers")  # ✅ Fetch only required columns
    officers = cur.fetchall()
    conn.close()
    return officers

# Function to fetch admin details from admin.db
def get_admin():
    conn = sqlite3.connect("admin.db")  # ✅ Connect to the correct DB
    cur = conn.cursor()
    cur.execute("SELECT full_name, phone, email, position FROM admin WHERE id=1")
    admin = cur.fetchone()
    conn.close()
    
    if admin:
        return {"name": admin[0], "phone": admin[1], "email": admin[2], "position": admin[3]}
    return None  # Handle case where admin is not found

@app.route('/admin/settings')
def admin_settings():
    section = request.args.get('section', 'profile')
    
    officers = get_officers()  # Fetch from access_control.db
    admin = get_admin()  # Fetch from admin.db

    if not admin:
        return "Admin not found", 404  # Handle error if admin doesn't exist

    return render_template('admin_settings.html', section=section, officers=officers, admin=admin)

@app.route('/update_access_control', methods=['POST'])
def update_access_control():
    data = request.get_json()
    officer_id = int(data['officer_id'])
    new_access_level = data['new_access_level']

    # Update access level in the database
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE officers SET access_level = ? WHERE id = ?", (new_access_level, officer_id))
    conn.commit()
    conn.close()

    return jsonify({"message": "Access level updated successfully!"})

@app.route("/edit_admin", methods=["POST"])
def edit_admin():
    name = request.form["name"]
    phone = request.form["phone"]
    email = request.form["email"]

    conn = sqlite3.connect("admin.db")  # ✅ Connect to admin DB
    cur = conn.cursor()
    cur.execute("UPDATE admin SET full_name=?, phone=?, email=? WHERE id=1", (name, phone, email))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_settings", section="profile"))

@app.route('/update_security_settings', methods=['POST'])
def update_security_settings():
    # Handle form submission logic here
    officer_actions = request.form.getlist('actions')
    print("Received security settings update:", officer_actions)  # Debugging output
    return redirect(url_for('admin_settings', section='security'))

def get_db_connection():
    conn = sqlite3.connect('user.db')
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn
    
@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if 'user_id' in session:  # If user is already logged in, redirect to home
        return redirect(url_for('user_home'))
    
    if request.method == 'POST':
        # Access form data
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Email and password are required!', 'error')
            return redirect(url_for('user_login'))

        # Debugging: Print form data
        print(f"Email: {email}, Password: {password}")

        # Check credentials in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Store user data in session
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['fullname'] = user['fullname']
            return redirect(url_for('user_home'))  # Redirect to user home page
        else:
            flash('Invalid email or password!', 'error')
            return redirect(url_for('user_login'))

    return render_template('user_login.html')

@app.route('/user_home')
def user_home():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('Please login to access this page!', 'error')
        return redirect(url_for('user_login'))

    # Fetch user details from the session
    user_id = session['user_id']
    email = session['email']
    fullname = session['fullname']

    return render_template('user_home.html', fullname=fullname, email=email)


@app.route('/user_signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        # Get form data
        fullname = request.form['fullname']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        aadhar = request.form['aadhar']
        state = request.form['state']
        district = request.form['district']
        police_station = request.form['police_station']

        # Handle file upload
        aadhar_card = request.files['aadhar_card']
        aadhar_card_filename = None
        if aadhar_card:
            aadhar_card_filename = os.path.join(app.config['UPLOAD_FOLDER'], aadhar_card.filename)
            aadhar_card.save(aadhar_card_filename)

        # Insert data into the database
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (fullname, email, phone, password, aadhar, state, district, police_station, aadhar_card_filename)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (fullname, email, phone, password, aadhar, state, district, police_station, aadhar_card_filename))
            conn.commit()
            flash('Signup successful! Please login.', 'success')
        except sqlite3.IntegrityError:
            flash('Email, phone, or Aadhar number already exists!', 'error')
        finally:
            conn.close()

        return redirect(url_for('user_signup'))

    return render_template('user_signup.html')

@app.route('/user_alert')
def user_alert():
    return render_template('user_alert.html')

@app.route('/user_settings', methods=['GET', 'POST'])
def user_settings():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))  # Redirect to login if not authenticated

    user_id = session['user_id']
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch user details
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        try:
            if password:  # If the user wants to update the password
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                cursor.execute("UPDATE users SET name=?, email=?, phone=?, password=? WHERE id=?",
                               (name, email, phone, hashed_password, user_id))
            else:
                cursor.execute("UPDATE users SET name=?, email=?, phone=? WHERE id=?",
                               (name, email, phone, user_id))

            conn.commit()
            flash("✅ Settings updated successfully!", "success")

        except sqlite3.IntegrityError:
            flash("⚠️ Email or Phone already exists!", "danger")

        conn.close()
        return redirect(url_for('user_settings'))  # Reload the settings page

    return render_template('user_settings.html', user=user)


@app.route('/user_logout')
def user_logout():
    session.clear()  # Clear user session
    flash("You have been logged out.", "info")
    return redirect(url_for('user_login'))

@app.route('/send_alert', methods=['POST'])
def send_alert():
    if 'user_id' not in session:
        return jsonify({"message": "User not logged in"}), 403

    data = request.get_json()
    location = data.get('location')
    district = data.get('district')

    if not location or not district:
        return jsonify({"message": "Location and district are required"}), 400

    try:
        # Get user details
        conn = sqlite3.connect("user.db")
        cursor = conn.cursor()
        cursor.execute("SELECT fullname, phone FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return jsonify({"message": "User not found"}), 404

        user_name, user_phone = user

        # ✅ Create `user_alert` table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_alert (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                location TEXT NOT NULL,
                district TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # ✅ Save the alert to the `user_alert` table
        cursor.execute("INSERT INTO user_alert (user_id, name, phone, location, district) VALUES (?, ?, ?, ?, ?)",
                       (session['user_id'], user_name, user_phone, location, district))
        conn.commit()
        conn.close()

        return jsonify({"message": "Alert saved successfully!"})

    except Exception as e:
        print("Error:", e)
        return jsonify({"message": "Internal server error"}), 500
    
@app.route('/user_case_status')
def user_case_status():
    if 'user_id' not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for('user_login'))

    user_name = session.get('fullname')  # Get logged-in user's name

    conn = sqlite3.connect("cases.db")
    cursor = conn.cursor()
    cursor.execute("SELECT case_number FROM cases WHERE reported_person = ?", (user_name,))
    user_cases = cursor.fetchall()
    conn.close()

    return render_template("user_case_status.html", cases=user_cases)

@app.route('/user_help')
def user_help():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))  # Redirect to login if not logged in
    return render_template('user_help.html')

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if 'user_id' not in session:
        return jsonify({"message": "User not logged in"}), 403

    data = request.json
    feedback_text = data.get('feedback')

    # Get the user's name from the session
    conn = sqlite3.connect("user.db")
    cursor = conn.cursor()
    cursor.execute("SELECT fullname FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"message": "User not found"}), 404

    user_name = user[0]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save feedback to user.db
    conn = sqlite3.connect("user.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO feedback (user_name, feedback, timestamp) VALUES (?, ?, ?)", 
                   (user_name, feedback_text, timestamp))
    conn.commit()
    conn.close()

    return jsonify({"message": "Feedback submitted successfully!"})

if __name__ == '__main__':
    app.run(debug=True)

