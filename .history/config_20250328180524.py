from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY').encode()
MYSQL_USER = os.getenv('secure_user')
MYSQL_PASSWORD = os.getenv('MySQL@root1')
MYSQL_DB = os.getenv('secure_db')
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if len(ENCRYPTION_KEY) not in [16, 24, 32]:
    raise ValueError("ENCRYPTION_KEY must be 16, 24, or 32 bytes long")
ENCRYPTION_KEY = ENCRYPTION_KEY.encode()
