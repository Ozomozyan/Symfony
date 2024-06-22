from flask import Flask, jsonify
import mysql.connector
from mysql.connector import errorcode

app = Flask(__name__)

def get_db_connection():
    conn = mysql.connector.connect(
        host='mysql-esat.alwaysdata.net',  # Adjust the host name
        database='esat_crisis',
        user='esat_2',
        password='C>3Gmt-4_2h3Fp)/'
    )
    return conn
except mysql.connector.Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
        print("Something is wrong with your user name or password")
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
        print("Database does not exist")
    else:
        print(err)
    return None

@app.route('/')
def hello_world():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM sectors')
    sectors = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(sectors)

@app.route('/sectors')
def show_sectors():
    conn = get_db_connection()
    if conn is not None:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sectors")
        sector_data = cursor.fetchall()
        cursor.close()
        conn.close()
        # Creating a list of dictionaries to store column names and data for JSON response
        columns = [column[0] for column in cursor.description]
        result = [dict(zip(columns, data)) for data in sector_data]
        return jsonify(result)
    else:
        return jsonify({"error": "Database connection failed"}), 500

if __name__ == '__main__':
    app.run(debug=True)
