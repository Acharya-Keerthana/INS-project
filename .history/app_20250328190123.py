import streamlit as st
import base64
import os
from rsa_encryption import encrypt_data, decrypt_data
from jwt_auth import generate_jwt, verify_jwt
from digital_signature import sign_document, verify_document

# Load RSA Public and Private Keys
with open("public_key.pem", "rb") as pub_file:
    PUBLIC_KEY = pub_file.read()

with open("private_key.pem", "rb") as priv_file:
    PRIVATE_KEY = priv_file.read()

st.title("🔒 Secure Data Transmission & Digital Signature System")

# Authentication
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
    except Exception:
        st.error("Decryption failed! Ensure you entered a valid encrypted message.")

# Digital Signature Section
st.header("✍️ Digital Signature for Documents")
uploaded_file = st.file_uploader("Upload a document to sign", type=["txt", "pdf", "docx"])
if uploaded_file:
    file_path = f"uploads/{uploaded_file.name}"
    with open(file_path, "wb") as f:
        f.write(uploaded_file.read())

    if st.button("Sign Document"):
        signature_path = sign_document(file_path)
        st.success(f"Document Signed! Signature stored at: {signature_path}")

# Verify Document Signature
st.subheader("🔍 Verify Signed Document")
verify_file = st.file_uploader("Upload Original Document", type=["txt", "pdf", "docx"])
verify_sig_file = st.file_uploader("Upload Corresponding Signature", type=["sig"])

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
