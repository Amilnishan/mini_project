import mysql.connector
import bcrypt
import getpass  # Hides password input for better security

# --- Database configuration remains the same ---
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Root@_123',
    'database': 'postal_sort'
}

def setup_initial_admin():
    """
    Connects to the DB and creates the very first admin user.
    This should only be run once during the initial application setup.
    """
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        print("--- Creating Initial Admin User ---")

        # First, check if an admin user already exists to prevent errors
        cursor.execute("SELECT user_id FROM Login WHERE role = 'admin'")
        if cursor.fetchone():
            print("\nAn admin user already exists. Aborting setup.")
            print("If you need to create a new one, you must do so from the database directly or delete the old one.")
            return

        # If no admin exists, proceed with creating one
        admin_username = input("Enter the username for the initial admin: ")
        # Use getpass to make password entry invisible
        admin_password = getpass.getpass("Enter the password for the initial admin: ")
        
        # Hash the password securely
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())

        # Insert the new admin into the Login table
        insert_admin_query = "INSERT INTO Login (username, password, role) VALUES (%s, %s, 'admin')"
        cursor.execute(insert_admin_query, (admin_username, hashed_password))
        
        conn.commit()
        print(f"\nAdmin user '{admin_username}' created successfully.")
        print("You can now start the Flask web server and log in.")

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
            print("MySQL connection is closed.")

# --- This part runs the function ---
if __name__ == '__main__':
    setup_initial_admin()