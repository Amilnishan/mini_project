print("---script is starting---")

# =======================================================
# 1. YOU MUST HAVE THESE IMPORTS AT THE TOP
# =======================================================
import mysql.connector
import bcrypt

# =======================================================
# 2. YOU NEED THE DATABASE CONFIGURATION
# =======================================================
db_config = {
    'host': 'localhost',
    'user': 'root', 
    'password': 'Root@_123', 
    'database': 'postal_sort'
}

# =======================================================
# 3. THE CODE MUST BE INSIDE A FUNCTION AND A TRY BLOCK
# =======================================================
def create_users():
    """Connects to the DB and creates a sample admin and staff user with hashed passwords."""
    try:
        # Connect to the database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # ===================================================================
        # THIS IS THE CODE SNIPPET YOU PASTED. IT NEEDS THE CODE ABOVE IT.
        # ===================================================================
        
        # --- Create a Staff Member First ---
        staff_name = "Alice Johnson"
        phone = "555-0101"
        
        # Check if staff already exists by name
        cursor.execute("SELECT staff_id FROM Staff WHERE staff_name = %s", (staff_name,))
        if cursor.fetchone() is None:
            # Insert staff member
            insert_staff_query = "INSERT INTO Staff (staff_name, phone) VALUES (%s, %s)"
            cursor.execute(insert_staff_query, (staff_name, phone))
            staff_id = cursor.lastrowid # Get the ID of the new staff member
            print(f"Staff member '{staff_name}' created with ID: {staff_id}")
        else:
            # If the staff member exists, we need to find their ID to link the login
            cursor.execute("SELECT staff_id FROM Staff WHERE staff_name = %s", (staff_name,))
            result = cursor.fetchone()
            staff_id = result[0]
            print(f"Staff member '{staff_name}' already exists with ID: {staff_id}.")
            
        # --- Create Admin User ---
        admin_username = "admin"
        admin_password = "admin123" # The password you will use to log in
        hashed_password_admin = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())

        # Check if admin user already exists
        cursor.execute("SELECT user_id FROM Login WHERE username = %s", (admin_username,))
        if cursor.fetchone() is None:
            insert_admin_query = "INSERT INTO Login (username, password, role) VALUES (%s, %s, 'admin')"
            cursor.execute(insert_admin_query, (admin_username, hashed_password_admin))
            print(f"Admin user '{admin_username}' created successfully.")
        else:
            print(f"Admin user '{admin_username}' already exists.")

        # --- Create Staff User ---
        staff_username = "alice"
        staff_password = "staff123" # The password you will use to log in
        hashed_password_staff = bcrypt.hashpw(staff_password.encode('utf-8'), bcrypt.gensalt())
        
        # Check if staff user already exists
        cursor.execute("SELECT user_id FROM Login WHERE username = %s", (staff_username,))
        if cursor.fetchone() is None:
            insert_staff_user_query = "INSERT INTO Login (username, password, role, staff_id) VALUES (%s, %s, 'staff', %s)"
            cursor.execute(insert_staff_user_query, (staff_username, hashed_password_staff, staff_id))
            print(f"Staff user '{staff_username}' created successfully.")
        else:
            print(f"Staff user '{staff_username}' already exists.")

        # Commit the changes
        conn.commit()

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
    finally:
        # Close the connection
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
            print("MySQL connection is closed.")

# =======================================================
# 4. YOU NEED THIS PART TO ACTUALLY RUN THE FUNCTION
# =======================================================
if __name__ == '__main__':
    create_users()