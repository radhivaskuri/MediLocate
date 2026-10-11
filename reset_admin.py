from werkzeug.security import generate_password_hash
from database import get_db_connection

new_password = "Admin@123"

connection = get_db_connection()
cursor = connection.cursor()

password_hash = generate_password_hash(new_password)

cursor.execute("""
    UPDATE users
    SET password_hash = %s,
        role = 'admin'
    WHERE email = %s
""", (password_hash, "admin@medilocate.com"))

connection.commit()

print("Admin password reset successfully!")

cursor.close()
connection.close()