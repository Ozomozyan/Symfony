from flask import Flask, jsonify
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
def home():
    return 'Hello, welcome to our crisis management system!'

if __name__ == '__main__':
    app.run(debug=True)
