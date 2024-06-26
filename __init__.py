from flask import Flask, jsonify, render_template, request, make_response, session, redirect, url_for, flash
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
        cursor = conn.cursor(dictionary=True)
        
        # Fetch user role information
        cursor.execute('SELECT role FROM personnel WHERE name = %s', (username,))
        role_info = cursor.fetchone()

        # Fetch sectors information
        cursor.execute('SELECT id, name FROM sectors')
        sectors = cursor.fetchall()
        
        if role_info:
            role = role_info['role']  # Access as a dictionary
            # Filter incidents based on the roles required using the correct column name
            cursor.execute('SELECT * FROM incidents WHERE FIND_IN_SET(%s, role_required)', (role,))
            incidents = cursor.fetchall()
        else:
            cursor.close()
            conn.close()
            return "Role information not found", 404
        
        cursor.close()
        conn.close()

        template_name = f"{role}_dashboard.html"
        return render_template(template_name, username=username, role=role, incidents=incidents, sectors=sectors)
    else:
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
    # Adding 'role_required' to store roles needed for the incident
    query = '''
    INSERT INTO incidents (sector_id, description, incident_type, role_required, start_time, status)
    VALUES (%s, %s, %s, %s, NOW(), 'ongoing')
    '''
    cursor.execute(query, (sector_id, description, incident_type, requires))
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

@app.route('/admin/users')
@auth.login_required
@role_required('admin')
def list_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM personnel')
    personnel = cursor.fetchall()
    cursor.execute('SELECT * FROM individuals')
    individuals = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('admin_users.html', personnel=personnel, individuals=individuals)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@auth.login_required
@role_required('admin')
def edit_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        role = request.form['role']
        cursor.execute('UPDATE personnel SET name = %s, role = %s WHERE id = %s', (name, role, user_id))
        conn.commit()
        return redirect(url_for('list_users'))

    cursor.execute('SELECT * FROM personnel WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/admin/edit_individual/<int:individual_id>', methods=['GET', 'POST'])
@auth.login_required
@role_required('admin')
def edit_individual(individual_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        health_status = request.form['health_status']
        is_quarantined = request.form.get('is_quarantined', type=bool)
        cursor.execute('UPDATE individuals SET name = %s, health_status = %s, is_quarantined = %s WHERE id = %s', 
                       (name, health_status, is_quarantined, individual_id))
        conn.commit()
        return redirect(url_for('list_users'))

    cursor.execute('SELECT * FROM individuals WHERE id = %s', (individual_id,))
    individual = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('edit_individual.html', individual=individual)

@app.route('/admin/edit_resource/<int:resource_id>', methods=['GET', 'POST'])
@auth.login_required
@role_required('admin')
def edit_resource(resource_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        resource_type = request.form['type']
        quantity = request.form['quantity']
        sector_id = request.form['sector_id']
        cursor.execute('UPDATE resources SET type = %s, quantity = %s, sector_id = %s WHERE id = %s', 
                       (resource_type, quantity, sector_id, resource_id))
        conn.commit()
        return redirect(url_for('admin_dashboard'))

    cursor.execute('SELECT * FROM resources WHERE id = %s', (resource_id,))
    resource = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('edit_resource.html', resource=resource)

@app.route('/edit_incident/<int:incident_id>', methods=['GET', 'POST'])
@auth.login_required
def edit_incident(incident_id):
    username = session.get('username')
    user_role = users.get(username, {}).get('role')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Set cursor to return dictionary
    cursor.execute('SELECT * FROM incidents WHERE id = %s', (incident_id,))
    incident = cursor.fetchone()

    if not incident:
        cursor.close()
        conn.close()
        return "Incident not found", 404

    # Access role_required using dictionary key
    required_roles = incident['role_required'].split(',') if incident['role_required'] else []

    if user_role != 'admin' and user_role not in required_roles:
        cursor.close()
        conn.close()
        return "Access Denied", 403

    if request.method == 'POST':
        description = request.form['description']
        incident_type = request.form['incident_type']
        role_required = ','.join(request.form.getlist('role_required'))
        status = request.form['status']

        cursor.execute('UPDATE incidents SET description = %s, incident_type = %s, role_required = %s, status = %s WHERE id = %s',
                       (description, incident_type, role_required, status, incident_id))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('dashboard'))

    cursor.close()
    conn.close()
    return render_template('edit_incident.html', incident=incident)




@app.route('/admin/add_resource', methods=['GET', 'POST'])
@auth.login_required
@role_required('admin')
def add_resource():
    if request.method == 'POST':
        resource_type = request.form['type']
        quantity = request.form['quantity']
        sector_id = request.form['sector_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO resources (type, quantity, sector_id) VALUES (%s, %s, %s)', (resource_type, quantity, sector_id))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for('admin_dashboard'))
    return render_template('add_resource.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        sector_id = int(request.form['sector'])  # Convert sector_id to integer
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        try:
            cursor.execute('INSERT INTO personnel (name, role, password) VALUES (%s, %s, %s)', (username, 'user', hashed_password))
            cursor.execute('INSERT INTO individuals (name, sector_id, health_status, is_quarantined) VALUES (%s, %s, "healthy", FALSE)', (username, sector_id))
            conn.commit()
            return "Registration successful"
        except mysql.connector.Error as e:
            conn.rollback()
            print(f"Failed to insert data: {e}")  # Debug output
            return f"Failed to register due to error: {e}", 500
        finally:
            cursor.close()
            conn.close()
    else:
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
