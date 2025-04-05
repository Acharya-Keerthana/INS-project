from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()


MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_DB = os.getenv("MYSQL_DB")

# Debugging print statements
print(f"User: {MYSQL_USER}, Database: {MYSQL_DB}")  # Ensure values are correctly loaded

ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if len(ENCRYPTION_KEY) not in [16, 24, 32]:
    raise ValueError("ENCRYPTION_KEY must be 16, 24, or 32 bytes long")
ENCRYPTION_KEY = ENCRYPTION_KEY.encode()
