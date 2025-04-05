import jwt
import datetime

SECRET_KEY = "your_jwt_secret_key"  # Change this to a strong secret

# Generate JWT Token
def generate_jwt(username):
    payload = {
        "user": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Verify JWT Token
def verify_jwt(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded["user"]
    except jwt.ExpiredSignatureError:
        return "Token expired!"
    except jwt.InvalidTokenError:
        return "Invalid token!"
