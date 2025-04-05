import streamlit as st
import base64
import os
import sqlite3
import hashlib
from rsa_encryption import encrypt_data, decrypt_data
from jwt_auth import generate_jwt, verify_jwt
from digital_signature import sign_document, verify_document

# Setup SQLite connection
conn = sqlite3.connect("users.db")
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT)')

# Utility functions for authentication
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    c.execute('INSERT INTO users(username, password) VALUES (?, ?)', (username, hash_password(password)))
    conn.commit()

def login_user(username, password):
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hash_password(password)))
    return c.fetchone()

# Load RSA Public and Private Keys
with open("public_key.pem", "rb") as pub_file:
    PUBLIC_KEY = pub_file.read()

with open("private_key.pem", "rb") as priv_file:
    PRIVATE_KEY = priv_file.read()

st.title("🔒 Secure Data Transmission & Digital Signature System")

# Sidebar Login/Register
menu = ["Login", "Register"]
choice = st.sidebar.selectbox("Choose Option", menu)

if choice == "Register":
    st.sidebar.subheader("Create New Account")
    new_user = st.sidebar.text_input("Username")
    new_pass = st.sidebar.text_input("Password", type='password')
    if st.sidebar.button("Register"):
        register_user(new_user, new_pass)
        st.sidebar.success("Account created! Please login.")

elif choice == "Login":
    st.sidebar.subheader("User Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type='password')
    if st.sidebar.button("Login"):
        user = login_user(username, password)
        if user:
            st.sidebar.success(f"Welcome, {username}!")
            st.session_state["user"] = username
        else:
            st.sidebar.error("Invalid credentials")

# Continue only if user is logged in
if "user" in st.session_state:
    username = st.session_state["user"]

    # Authentication Token
    st.sidebar.header("🔑 Authentication")
    if st.sidebar.button("Generate JWT Token"):
        token = generate_jwt(username)
        st.sidebar.success(f"Your JWT Token: {token}")

    # Verify JWT Token
    st.sidebar.subheader("Verify JWT")
    verify_token = st.sidebar.text_input("Enter JWT Token")
    if st.sidebar.button("Verify Token"):
        user = verify_jwt(verify_token)
        if user:
            st.sidebar.success(f"Authenticated User: {user}")
        else:
            st.sidebar.error("Invalid Token")

    # Encryption Section
    st.header("🔐 RSA Encryption & Decryption")
    message = st.text_area("Enter Message to Encrypt")
    if st.button("Encrypt"):
        encrypted_data = encrypt_data(PUBLIC_KEY, message)
        st.success(f"Encrypted Message: {base64.b64encode(encrypted_data).decode()}")

    # Decryption Section
    encrypted_input = st.text_area("Enter Encrypted Text to Decrypt (Base64)")
    if st.button("Decrypt"):
        try:
            encrypted_bytes = base64.b64decode(encrypted_input.encode())
            decrypted_data = decrypt_data(PRIVATE_KEY, encrypted_bytes)
            st.success(f"Decrypted Message: {decrypted_data}")
        except Exception:
            st.error("Decryption failed! Ensure you entered a valid encrypted message.")

    # Digital Signature Section
    st.header("✍️ Digital Signature for Documents")
    uploaded_file = st.file_uploader("Upload a document to sign", type=["txt", "pdf", "docx"])
    if uploaded_file:
        os.makedirs("uploads", exist_ok=True)
        file_path = f"uploads/{uploaded_file.name}"
        with open(file_path, "wb") as f:
            f.write(uploaded_file.read())

        if st.button("Sign Document"):
            signature_path = sign_document(file_path)
            st.success(f"Document Signed! Signature stored at: {signature_path}")

    # Verify Document Signature
    st.subheader("🔍 Verify Signed Document")
    verify_file = st.file_uploader("Upload Original Document", type=["txt", "pdf", "docx"], key="verify_file")
    verify_sig_file = st.file_uploader("Upload Corresponding Signature", type=["sig"], key="verify_sig")

    if verify_file and verify_sig_file:
        verify_file_path = f"uploads/{verify_file.name}"
        with open(verify_file_path, "wb") as f:
            f.write(verify_file.read())

        verify_sig_path = f"uploads/{verify_sig_file.name}"
        with open(verify_sig_path, "wb") as f:
            f.write(verify_sig_file.read())

        if st.button("Verify Signature"):
            if verify_document(verify_file_path, verify_sig_path):
                st.success("✅ Signature is valid! Document is authentic.")
            else:
                st.error("❌ Signature verification failed! The document may be tampered with.")

    st.info("Ensure you are using HTTPS for secure transmission.")
else:
    st.warning("Please login to access the secure features.")
