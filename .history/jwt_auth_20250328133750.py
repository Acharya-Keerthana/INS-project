import jwt
import datetime
from config import ENCRYPTION_KEY  # Using the AES key as a secret

SECRET_KEY = ENCRYPTION_KEY  # JWT secret

def generate_jwt(user_id):
    """Generate JWT token."""
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_jwt(token):
    """Verify JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return "Token expired"
    except jwt.InvalidTokenError:
        return "Invalid token"

# Example Usage
token = generate_jwt(user_id=1)
print("JWT Token:", token)
print("Verified:", verify_jwt(token))
