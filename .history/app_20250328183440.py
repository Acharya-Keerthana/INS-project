import streamlit as st
import base64
from rsa_encryption import encrypt_data, decrypt_data
from auth import generate_jwt, verify_jwt

# Load RSA Public and Private Keys
with open("public_key.pem", "rb") as pub_file:
    PUBLIC_KEY = pub_file.read()

with open("private_key.pem", "rb") as priv_file:
    PRIVATE_KEY = priv_file.read()

st.title("🔒 Secure Data Transmission App")

# Login Section
st.sidebar.header("🔑 Authentication")
username = st.sidebar.text_input("Username")
if st.sidebar.button("Generate JWT Token"):
    token = generate_jwt(username)
    st.sidebar.success(f"Your JWT Token: {token}")

# Verify JWT Token
st.sidebar.subheader("Verify JWT")
verify_token = st.sidebar.text_input("Enter JWT Token")
if st.sidebar.button("Verify Token"):
    user = verify_jwt(verify_token)
    st.sidebar.success(f"Authenticated User: {user}")

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
    except Exception as e:
        st.error("Decryption failed! Ensure you entered a valid encrypted message.")

st.info("Ensure you are using HTTPS for secure transmission.")
