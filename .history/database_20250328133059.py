import mysql.connector
from config import MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
from encryption import AESCipher, ENCRYPTION_KEY

# Establish a secure connection
conn = mysql.connector.connect(
    host="localhost",
    user=MYSQL_USER,
    password=MYSQL_PASSWORD,
    database=MYSQL_DB
)

cursor = conn.cursor()

# Create a table to store encrypted data
cursor.execute("""
    CREATE TABLE IF NOT EXISTS secure_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        encrypted_value TEXT NOT NULL
    )
""")
conn.commit()

aes_cipher = AESCipher(ENCRYPTION_KEY)

# Function to insert encrypted data
def insert_secure_data(plain_text):
    encrypted_text = aes_cipher.encrypt(plain_text)
    cursor.execute("INSERT INTO secure_data (encrypted_value) VALUES (%s)", (encrypted_text,))
    conn.commit()
    print("Data inserted securely.")

# Function to retrieve and decrypt data
def get_secure_data():
    cursor.execute("SELECT encrypted_value FROM secure_data")
    rows = cursor.fetchall()
    for row in rows:
        decrypted_text = aes_cipher.decrypt(row[0])
        print("Decrypted:", decrypted_text)

# Example Usage
insert_secure_data("Confidential Information")
get_secure_data()

cursor.close()
conn.close()
