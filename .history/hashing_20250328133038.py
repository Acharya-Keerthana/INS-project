import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# Example Usage
hashed_pw = hash_password("SecurePassword123")
print("Hashed Password:", hashed_pw)
print("Verification:", verify_password("SecurePassword123", hashed_pw))
