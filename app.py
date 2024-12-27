from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps
import os
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Secret key for JWT
SECRET_KEY = os.getenv("SECRET_KEY", "your_default_secret_key")
app.config['SECRET_KEY'] = SECRET_KEY

# Configure logging
logging.basicConfig(level=logging.INFO)

# MongoDB connection (replace with your correct MongoDB connection string)
try:
    client = MongoClient(os.getenv("MONGODB_URI", "mongodb+srv://geteazr:Eazr%402024@sample.kuy4nlt.mongodb.net/admin?retryWrites=true&loadBalanced=false&replicaSet=atlas-kdnqpy-shard-0&srvServiceName=mongodb&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-1"))
    db = client['eazr_DB']
    users_collection = db['user_auth']  # MongoDB Collection for users

    # Test MongoDB connection
    db.command('ping')
    logging.info("Connected to MongoDB successfully")
except Exception as e:
    logging.error(f"Could not connect to MongoDB: {e}")
    raise Exception(f"MongoDB Connection Error: {e}")

# Allowed IPs
ALLOWED_IPS = ["192.168.1.12", "127.0.0.1","192.168.1.18","192.168.1.22"]  # Add your allowed IPs here

# Decorator to check client IP
def ip_restricted(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        logging.info(f"Client IP: {client_ip}")
        if client_ip not in ALLOWED_IPS:
            logging.error(f"Unauthorized IP: {client_ip}")
            return jsonify({'message': f'Unauthorized IP: {client_ip}'}), 403
        return f(*args, **kwargs)
    return decorated

# Decorator to require valid JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        logging.info(f"Token received: {token}")

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            token = token.split()[1]  # Extract the token after 'Bearer'
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({"user_id": data['user_id']})

            if not current_user:
                raise Exception("User not found")

        except Exception as e:
            logging.error(f"Token validation error: {e}")
            return jsonify({'message': f'Invalid Token: {str(e)}'}), 403

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
def auth():
    return 'User Authentication API is working'

# Registration API
@app.route('/register', methods=['POST'])
@ip_restricted
def register():
    try:
        data = request.json
        user_id = data.get('user_id')
        username = data.get('username')
        password = data.get('password')

        if not all([user_id, username, password]):
            return jsonify({'message': 'Missing required fields'}), 400

        # Check if user already exists
        if users_collection.find_one({"user_id": user_id}):
            return jsonify({'message': 'User already exists'}), 400

        # Correct hashing method
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        users_collection.insert_one({
            'user_id': user_id,
            'username': username,
            'password': hashed_password,
        })

        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        logging.error(f"Error during registration: {e}")
        return jsonify({'message': f'Error during registration: {str(e)}'}), 500

# Login API
@app.route('/login', methods=['POST'])
@ip_restricted
def login():
    try:
        data = request.json
        user_id = data.get('user_id')
        password = data.get('password')

        user = users_collection.find_one({"user_id": user_id})
        if not user or not check_password_hash(user['password'], password):
            logging.error("Invalid credentials")
            return jsonify({'message': 'Invalid credentials'}), 403

        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'message': 'Login successful', 'token': token}), 200
    except Exception as e:
        logging.error(f"Error during login: {e}")
        return jsonify({'message': f'Error during login: {str(e)}'}), 500

# Secure Endpoint API
@app.route('/secure-endpoint', methods=['GET'])
@ip_restricted
@token_required
def secure_endpoint(current_user):
    return jsonify({
        'message': 'This is a secure endpoint.',
        'user': {
            'user_id': current_user['user_id'],
            'username': current_user['username']
        }
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
