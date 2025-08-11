from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
import bcrypt

app = Flask(__name__)

# A secret key is required for session management
app.secret_key = 'your_super_secret_key'

# --- IMPORTANT: CONFIGURE YOUR DATABASE CONNECTION ---
db_config = {
    'host': 'localhost',
    'user': 'root', --
    'password': 'Root@_123',
    'database': 'postal_sort'
}

def get_db_connection():
    """Creates and returns a new database connection."""
    conn = mysql.connector.connect(**db_config)
    return conn

# --- Middleware to Prevent Caching ---

@app.after_request
def set_no_cache_headers(response):
    """
    Adds headers to every response to prevent caching.
    This is crucial for security, especially after a logout.
    """
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# --- Public Routes ---

@app.route("/")
def landing_page():
    """Renders the main landing page."""
    return render_template("landing_page.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    """Handles the login process."""
    if request.method == 'POST':
        # Get form fields
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True) # dictionary=True lets us access columns by name

        # Fetch the user from the database
        cursor.execute("SELECT * FROM Login WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            # If user exists and password is correct, create a session
            session['loggedin'] = True
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            # Redirect to the appropriate dashboard based on role
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('staff_dashboard'))
        else:
            # If login fails, show an error message
            flash('Incorrect username or password. Please try again.', 'danger')
            return redirect(url_for('login'))

    # If it's a GET request, just show the login page
    return render_template("login.html")

@app.route("/logout")
def logout():
    """Logs the user out by clearing the session."""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# --- Protected Routes (Require Login) ---

@app.route("/admin/dashboard")
def admin_dashboard():
    """Renders the admin's main dashboard page."""
    # Check if the user is logged in and is an admin
    if 'loggedin' in session and session['role'] == 'admin':
        return render_template('admin_dashboard.html', username=session['username'])
    # If not logged in or not an admin, redirect to login
    return redirect(url_for('login'))

@app.route("/admin/manage_staff", methods=['GET', 'POST'])
def manage_staff():
    """
    Handles viewing staff list (GET) and adding new staff (POST).
    Only accessible to admins.
    """
    # First, check if user is logged in and is an admin
    if 'loggedin' not in session or session['role'] != 'admin':
        flash('You must be logged in as an admin to view this page.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # --- HANDLE POST REQUEST (Adding a new staff member) ---
    if request.method == 'POST':
        # Get form data
        staff_name = request.form['staff_name']
        phone = request.form['phone']
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # Hash the password for security
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        try:
            # Step 1: Insert into Staff table
            cursor.execute("INSERT INTO Staff (staff_name, phone) VALUES (%s, %s)", (staff_name, phone))
            staff_id = cursor.lastrowid # Get the ID of the new staff member

            # Step 2: Insert into Login table using the new staff_id
            cursor.execute(
                "INSERT INTO Login (username, password, role, staff_id) VALUES (%s, %s, 'staff', %s)",
                (username, hashed_password, staff_id)
            )
            conn.commit() # Commit both changes together
            flash('New staff member added successfully!', 'success')

        except mysql.connector.Error as err:
            # Handle potential errors, like a duplicate username or invalid phone
            err_str = str(err).lower()
            if err.errno == 1062 and 'username' in err_str:
                flash('Username already exists. Please choose a different username.', 'danger')
            elif 'phone' in err_str or 'invalid' in err_str:
                flash('Invalid phone number. Please enter a valid phone number.', 'danger')
            else:
                flash(f"Database error: {err}", 'danger')
        finally:
            cursor.close()
            conn.close()
        
        return redirect(url_for('manage_staff')) # Redirect to refresh the page


    # --- HANDLE GET REQUEST (Displaying the staff list) ---
    # This query joins Staff and Login tables to get all info
    cursor.execute("""
        SELECT s.staff_id, s.staff_name, s.phone, s.joined_date, s.status, l.username
        FROM Staff s
        JOIN Login l ON s.staff_id = l.staff_id
        ORDER BY s.staff_id
    """)
    staff_list = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('manage_staff.html', staff_list=staff_list, username=session['username'])

@app.route("/admin/edit_staff/<int:staff_id>", methods=['GET', 'POST'])
def edit_staff(staff_id):
    """Handles editing an existing staff member."""
    if 'loggedin' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        # Get data from the submitted form
        staff_name = request.form['staff_name']
        phone = request.form['phone']
        username = request.form['username']
        new_password = request.form['password']
        status = request.form['status']
        
        try:
            # Update the Staff table
            cursor.execute("""
                UPDATE Staff SET staff_name = %s, phone = %s, status = %s
                WHERE staff_id = %s
            """, (staff_name, phone, status, staff_id))

            # Update the Login table username
            cursor.execute("UPDATE Login SET username = %s WHERE staff_id = %s", (username, staff_id))
            
            # Only update the password if a new one was entered
            if new_password:
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("UPDATE Login SET password = %s WHERE staff_id = %s", (hashed_password, staff_id))
            
            conn.commit()
            flash('Staff details updated successfully!', 'success')
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", 'danger')
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('manage_staff'))

    # For a GET request, fetch the user's current data and show the edit form
    cursor.execute("""
        SELECT s.staff_id, s.staff_name, s.phone, s.status, l.username
        FROM Staff s
        JOIN Login l ON s.staff_id = l.staff_id
        WHERE s.staff_id = %s
    """, (staff_id,))
    staff = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    return render_template('edit_staff.html', staff=staff, username=session['username'])

@app.route("/staff/dashboard")
def staff_dashboard():
    """Renders the staff's main dashboard page."""
    # Check if the user is logged in and is a staff member
    if 'loggedin' in session and session['role'] == 'staff':
        return render_template('staff_dashboard.html', username=session['username'])
    # If not logged in or not staff, redirect to login
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)