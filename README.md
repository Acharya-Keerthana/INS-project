# 🔐 Secure Data Handling System

This project is a **Secure Data Handling System** that uses modern cryptographic techniques like **RSA encryption**, **JWT authentication**, **hashing**, and **digital signatures** to ensure the safe processing, storage, and transfer of sensitive data.

---

## 🔒 Features

- ✅ RSA key generation and secure encryption  
- 🔑 JWT-based user authentication  
- 🔐 SHA hashing for password protection  
- 📝 Digital signature for data verification  
- 🗃️ SQLite database for persistent storage  
- ⚙️ Environment variable support with `.env`

---

## 🛠️ Tech Stack

- Python  
- SQLite  
- PyJWT  
- cryptography  
- hashlib  
- python-dotenv

---

## 📁 Project Structure

```
ins project/
├── app.py                 # Main application logic
├── config.py              # Configuration settings
├── database.py            # Database interaction
├── digital_signature.py   # Digital signature utilities
├── encryption.py          # Encryption and decryption
├── generate_securekey.py  # RSA key generation
├── hashing.py             # Hashing functions
├── jwt_auth.py            # JWT creation and verification
├── rsa_encryption.py      # RSA encryption operations
├── users.db               # SQLite database
├── private_key.pem        # RSA private key
├── public_key.pem         # RSA public key
├── .env                   # Environment variables
└── README.md              # Project documentation
```

---

## ⚙️ Setup Instructions

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd "ins project"
```

### 2. Create a virtual environment (optional but recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

---

## ▶️ Video Demo

Watch the project in action here:  
**[Video Demo Link – _insert your link here_]**

---


⭐ _If you found this project useful, consider giving it a star!_
