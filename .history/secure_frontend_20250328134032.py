import streamlit as st
import requests

BASE_URL = "https://localhost:5000"  # Use HTTPS

st.title("Secure Data Transmission")

if st.button("Login"):
    response = requests.post(f"{BASE_URL}/login", json={"username": "admin", "password": "password"}, verify=False)
    if response.status_code == 200:
        token = response.json()["token"]
        st.session_state["token"] = token
        st.success("Logged in successfully!")
    else:
        st.error("Login failed.")

if "token" in st.session_state:
    st.header("Send Secure Data")
    data_to_encrypt = st.text_input("Enter data to encrypt:")
    if st.button("Encrypt & Send"):
        response = requests.post(f"{BASE_URL}/secure-data", json={"data": data_to_encrypt}, verify=False)
        st.write("Encrypted Data:", response.json()["encrypted"])
    
    st.header("Retrieve Decrypted Data")
    encrypted_data = st.text_input("Enter encrypted data:")
    if st.button("Decrypt"):
        response = requests.post(f"{BASE_URL}/decrypt-data", json={"encrypted": encrypted_data}, verify=False)
        st.write("Decrypted Data:", response.json()["decrypted"])
