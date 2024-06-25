from flask import Flask, jsonify, render_template, request, make_response, session, redirect, url_for
from flask_httpauth import HTTPBasicAuth
import mysql.connector
import bcrypt

app = Flask(__name__)
auth = HTTPBasicAuth()
app.secret_key = "=%p#UHtG?89|9/v.Ab46E1aDRuEI}B"

users = {
    "admin": {"password": "adminpass", "role": "admin"},
    "doctor": {"password": "docpass", "role": "doctor"},
    "security": {"password": "secpass", "role": "security"},
    "user": {"password": "userpass", "role": "user"}  # Normal user
}


@auth.verify_password
def verify_password(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password, role FROM personnel WHERE name = %s', (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user and bcrypt.checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
        users[username] = {"password": user[0], "role": user[1]}  # Update the users dict dynamically
        return username

    
from functools import wraps

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = auth.current_user()
            if not user or users[user]['role'] != role:
                return make_response(jsonify({"error": "Permission denied"}), 403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator



def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host='mysql-esat.alwaysdata.net',  # Adjust the host name
            database='esat_crisis',
            user='esat_2',
            password='C>3Gmt-4_2h3Fp)/'
        )
        return conn
    except mysql.connector.Error as err:
        print("Error connecting to MySQL: ", err)
        return None

@app.route('/')
def home():
    return render_template('hello.html')

@app.route('/sectors')
def sectors():
    conn = get_db_connection()
    if conn is not None:
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT * FROM sectors')
            sectors_data = cursor.fetchall()
            cursor.close()
            conn.close()
            return jsonify(sectors_data)
        except mysql.connector.Error as err:
            print("Error querying MySQL: ", err)
            return jsonify({"error": "Error querying database"}), 500
    else:
        return jsonify({"error": "Database connection failed"}), 500
    
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM personnel WHERE name = %s', (username,))
        role_info = cursor.fetchone()
        
        cursor.execute('SELECT * FROM sectors')
        sectors = cursor.fetchall()

        cursor.close()
        conn.close()
        
        if role_info:
            role = role_info[0]
            template_name = f"{role}_dashboard.html"
            return render_template(template_name, username=username, sectors=sectors)
        else:
            return "Role information not found", 404
    return redirect(url_for('login'))




@app.route('/report_incident', methods=['POST'])
@auth.login_required
def report_incident():
    description = request.form['description']
    sector_id = request.form['sector']
    incident_type = request.form['incident_type']
    requires = ','.join(request.form.getlist('requires'))  # Handle multiple selections

    conn = get_db_connection()
    cursor = conn.cursor()
    query = '''INSERT INTO incidents (sector_id, description, incident_type, start_time, status)
               VALUES (%s, %s, %s, NOW(), 'ongoing')'''
    cursor.execute(query, (sector_id, description, incident_type))
    conn.commit()
    cursor.close()
    conn.close()
    return "Incident reported successfully"



@app.route('/update_resource/<int:resource_id>', methods=['PUT'])
@auth.login_required
@role_required('admin')
def update_resource(resource_id):
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    query = '''UPDATE resources SET quantity = %s WHERE id = %s'''
    cursor.execute(query, (data['quantity'], resource_id))
    conn.commit()
    cursor.close()
    conn.close()
    return "Resource updated successfully", 200

@app.route('/update_status', methods=['POST'])
@auth.login_required
@role_required('user')
def update_status():
    user = auth.current_user()
    status = request.form['health_status']
    conn = get_db_connection()
    cursor = conn.cursor()
    query = 'UPDATE individuals SET health_status = %s WHERE name = %s'
    cursor.execute(query, (status, user))
    conn.commit()
    cursor.close()
    conn.close()
    return "Health status updated successfully"

@app.route('/admin_dashboard')
@auth.login_required
@role_required('admin')
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM incidents')
    incidents = cursor.fetchall()
    cursor.execute('SELECT * FROM resources')
    resources = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('admin_dashboard.html', user=auth.current_user(), incidents=incidents, resources=resources)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        sector_id = request.form['sector']
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        # Set up the default role
        default_role = 'user'  # You can change 'user' to whatever role is considered a normal user

        conn = get_db_connection()
        cursor = conn.cursor()
        # Insert into personnel
        cursor.execute('INSERT INTO personnel (name, role, password) VALUES (%s, %s, %s)', (username, default_role, hashed_password))
        # Insert into individuals
        cursor.execute('INSERT INTO individuals (name, sector_id, health_status, is_quarantined) VALUES (%s, %s, "healthy", FALSE)', (username, sector_id))
        conn.commit()
        cursor.close()
        conn.close()
        return "Registration successful"
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM sectors')
        sectors = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('register.html', sectors=sectors)



# Modify the login function to set up the session
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM personnel WHERE name = %s', (username,))
        user_pass = cursor.fetchone()
        cursor.close()
        conn.close()

        if user_pass and bcrypt.checkpw(password, user_pass[0].encode('utf-8')):
            session['username'] = username  # Store username in session
            return "Login successful"
        else:
            return "Invalid username or password"
    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True, ssl_context='adhoc')  # Flask will generate a self-signed certificate
