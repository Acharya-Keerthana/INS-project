from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY').encode()
MYSQL_USER = os.getenv('MYSQL_USER')
MYSQL_PASSWORD = os.getenv('MySQ')
MYSQL_DB = os.getenv('secure_db')
