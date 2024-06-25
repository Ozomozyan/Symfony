from flask import Flask, jsonify, render_template, request, make_response
from flask_httpauth import HTTPBasicAuth
import mysql.connector

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "admin": {"password": "adminpass", "role": "admin"},
    "doctor": {"password": "docpass", "role": "doctor"},
    "security": {"password": "secpass", "role": "security"},
    "user": {"password": "userpass", "role": "user"}  # Normal user
}


@auth.verify_password
def verify_password(username, password):
    user = users.get(username)
    if user and user['password'] == password:
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
@auth.login_required
def dashboard():
    role = users[auth.current_user()]['role']
    incidents = None
    if role in ['doctor', 'security']:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM incidents WHERE incident_type = %s', (role,))
        incidents = cursor.fetchall()
        cursor.close()
        conn.close()

    template_name = f"{role}_dashboard.html"
    return render_template(template_name, user=auth.current_user(), incidents=incidents)


@app.route('/report_incident', methods=['POST'])
@auth.login_required
def report_incident():
    description = request.form['description']
    requires = request.form['requires']
    # Assuming 'sector_id' needs to be provided or determined in some way
    sector_id = 1  # Placeholder value

    conn = get_db_connection()
    cursor = conn.cursor()
    query = '''INSERT INTO incidents (sector_id, description, incident_type, start_time, status)
               VALUES (%s, %s, %s, NOW(), 'pending')'''
    cursor.execute(query, (sector_id, description, requires))
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
        password = request.form['password']
        # Here you should add password hashing for security
        hashed_password = password  # Placeholder for hashing
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO personnel (name, role, password) VALUES (%s, %s, %s)', (username, 'user', hashed_password))
        conn.commit()
        cursor.close()
        conn.close()
        return "Registration successful"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM personnel WHERE name = %s', (username,))
        user_pass = cursor.fetchone()
        cursor.close()
        conn.close()

        if user_pass and user_pass[0] == password:  # Simple comparison, use hashed passwords in production
            # Log the user in (set up session or token)
            return "Login successful"
        else:
            return "Invalid username or password"
    return render_template('login.html')


if __name__ == "__main__":
    app.run(debug=True)
