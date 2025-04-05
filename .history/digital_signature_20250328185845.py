import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Load Private Key for Signing
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# Load Public Key for Verification
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# Function to Sign a Document
def sign_document(file_path):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        # Hash the document
        document_hash = hashlib.sha256(file_data).digest()
        
        # Generate Digital Signature
        signature = private_key.sign(
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Save signature to a file
        signature_file = file_path + ".sig"
        with open(signature_file, "wb") as sig_file:
            sig_file.write(signature)
        
        return signature_file
    except Exception as e:
        return f"Error signing document: {str(e)}"

# Function to Verify a Signed Document
def verify_document(file_path, signature_path):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()
        
        # Hash the document
        document_hash = hashlib.sha256(file_data).digest()
        
        # Verify the Digital Signature
        public_key.verify(
            signature,
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
