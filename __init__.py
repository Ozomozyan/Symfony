from flask import Flask, jsonify
from flask import render_template
import mysql.connector

app = Flask(__name__)

def get_db_connection():
    conn = mysql.connector.connect(
        host='mysql-esat.alwaysdata.net',  # Adjust the host name
        database='esat_crisis',
        user='esat_2',
        password='C>3Gmt-4_2h3Fp)/'
    )
    return conn

@app.route('/')                                                                                                                                                        
def hello_world():                                                                                                                                                     
    return render_template('hello.html') 

@app.route('/try')
def hello_world():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM sectors')
    sectors = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(sectors)

if __name__ == "__main__":                                                                                                                                             
  app.run(debug=True)
