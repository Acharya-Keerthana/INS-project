from flask import Flask, request, jsonify
from jwt_auth import generate_jwt, verify_jwt
from rsa_encryption import encrypt_data, decrypt_data
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Load RSA keys
with open("rsa_private.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

with open("rsa_public.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

@app.route("/secure-data", methods=["POST"])
def secure_data():
    """Encrypt incoming data and return it."""
    data = request.json.get("data")
    encrypted = encrypt_data(data, public_key)
    return jsonify({"encrypted": encrypted.hex()})

@app.route("/decrypt-data", methods=["POST"])
def decrypt_data_api():
    """Decrypt received encrypted data."""
    encrypted_hex = request.json.get("encrypted")
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted = decrypt_data(encrypted_bytes, private_key)
    return jsonify({"decrypted": decrypted})

@app.route("/login", methods=["POST"])
def login():
    """Authenticate user and return JWT."""
    username = request.json.get("username")
    password = request.json.get("password")
    
    # In real applications, verify username and password
    if username == "admin" and password == "password":
        token = generate_jwt(user_id=1)
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/protected", methods=["GET"])
def protected():
    """Protected route requiring JWT authentication."""
    token = request.headers.get("Authorization")
    if token:
        verification = verify_jwt(token)
        if isinstance(verification, dict):
            return jsonify({"message": "Access granted", "user": verification})
    return jsonify({"error": "Unauthorized"}), 401

if __name__ == "__main__":
    app.run(ssl_context=("certificate.crt", "private.key"))  # Running with HTTPS
