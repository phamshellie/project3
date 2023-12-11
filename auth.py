from flask import Blueprint, request, jsonify
import sqlite3
import uuid
import argon2

auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route('/register', methods=['POST'])
def register():
    user_data = request.json

    username = user_data.get('username')
    email = user_data.get('email')

    if not (username and email):
        return jsonify({"error": "Username and email are required"}), 400

    #secure password using UUIDv4
    secure_password = str(uuid.uuid4())

    #hash password using Argon2
    argon2_hasher = argon2.PasswordHasher()
    hashed_password = argon2_hasher.hash(secure_password)

    try:
        conn = sqlite3.connect('my_database.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (username, password_hash, email)
            VALUES (?, ?, ?)
        ''', (username, hashed_password, email))
        
        conn.commit()
        conn.close()

        return jsonify({"password": secure_password}), 201

    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": "Failed to register user"}), 500

@auth_blueprint.route('/auth', methods=['POST'])
def authenticate():
    request_ip = request.remote_addr
    request_timestamp = None 
    username = request.json.get('username')
    password = request.json.get('password')

    try:
        conn = sqlite3.connect('my_database.db')
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, password_hash FROM users WHERE username = ?
        ''', (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        user_id, hashed_password = user
        argon2_hasher = argon2.PasswordHasher()

        try:
            argon2_hasher.verify(hashed_password, password)
            #log the request
            cursor.execute('''
                INSERT INTO auth_logs (request_ip, request_timestamp, user_id)
                VALUES (?, ?, ?)
            ''', (request_ip, request_timestamp, user_id))

            conn.commit()
            return jsonify({"message": "Authentication successful"}), 200

        except argon2.exceptions.VerifyMismatchError:
            return jsonify({"error": "Invalid password"}), 401

    except sqlite3.Error as e:
        return jsonify({"error": "Database error"}), 500

    finally:
        conn.close()
