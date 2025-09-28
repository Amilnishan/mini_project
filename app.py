from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response,Response
import mysql.connector
import bcrypt
import os
import re
import cv2
import numpy as np
import pytesseract
import base64
import easyocr
from PIL import Image, ImageEnhance
import io
import time
import traceback
from datetime import datetime, timedelta  # Added timedelta for timezone adjustment
from weasyprint import HTML, CSS

# CONFIGURE TESSERACT *BEFORE* YOU CREATE THE FLASK APP
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Initialize EasyOCR Reader
print("Initializing EasyOCR Reader...")
reader = easyocr.Reader(['en'])
print("EasyOCR Reader initialized successfully.")

app = Flask(__name__)

# A secret key is required for session management
app.secret_key = 'your_super_secret_key'

# --- IMPORTANT: CONFIGURE YOUR DATABASE CONNECTION ---
db_config = {
    'host': 'localhost',
    'user': 'root',
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
            session['staff_id'] = user['staff_id']  # Store staff_id if available
            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Use local time for session start
            
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

@app.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    
    # Create response with cache control headers and redirect to login page
    response = make_response(redirect(url_for('login') + '?logout=true'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

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

        # Validate phone number: only digits allowed
        if not re.fullmatch(r'\d+', phone):
            flash('Phone number must contain only digits.', 'danger')
            return redirect(url_for('manage_staff'))

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
        ORDER BY s.staff_id DESC
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

@app.route("/admin/history")
def admin_history():
    """Renders a page showing all sorting history, with optional date filters."""
    if 'loggedin' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    try:
        # Get date filters from the request URL's query parameters (e.g., ?start_date=...)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Start building the base SQL query
        base_query = """
            SELECT 
                si.sort_id, si.parcel_id, si.sorted_time,
                p.image_path,
                b.bin_name, b.pin,
                s.staff_name
            FROM sorted_item si
            JOIN Parcel p ON si.parcel_id = p.parcel_id
            JOIN Bin b ON si.bin_id = b.bin_id
            JOIN Staff s ON si.staff_id = s.staff_id
        """
        
        # Dynamically add WHERE clauses based on the filters provided
        conditions = []
        params = []
        
        if start_date:
            conditions.append("si.sorted_time >= %s")
            # Add time component to include the whole day
            params.append(f"{start_date} 00:00:00")
        
        if end_date:
            conditions.append("si.sorted_time <= %s")
            # Add time component to include the whole day
            params.append(f"{end_date} 23:59:59")

        # If there are any conditions, join them with AND
        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)

        # Always order the results
        base_query += " ORDER BY si.sorted_time DESC"

        cursor.execute(base_query, tuple(params))
        history_items = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template(
            'admin_history.html', 
            history_items=history_items, 
            username=session['username']
        )
        
    except Exception as e:
        traceback.print_exc()
        flash(f"A database error occurred: {e}", 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route("/staff/dashboard")
def staff_dashboard():
    """Renders the staff's main dashboard page."""
    # Check if the user is logged in and is a staff member
    if 'loggedin' in session and session['role'] == 'staff':
        return render_template('staff_dashboard.html', username=session['username'])
    # If not logged in or not staff, redirect to login
    return redirect(url_for('login'))  

def preprocess_image_for_ocr(img):
    """
    Enhanced image preprocessing for better OCR accuracy with noise reduction.
    """
    # Convert to PIL Image for better processing
    pil_img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    
    # 1. Resize image to optimal size (OCR works better with larger images)
    width, height = pil_img.size
    if width < 800:
        scale_factor = 800 / width
        new_width = int(width * scale_factor)
        new_height = int(height * scale_factor)
        pil_img = pil_img.resize((new_width, new_height), Image.Resampling.LANCZOS)
    
    # 2. Enhance contrast moderately
    enhancer = ImageEnhance.Contrast(pil_img)
    pil_img = enhancer.enhance(1.3)  # Reduced from 1.5
    
    # 3. Apply slight sharpening
    enhancer = ImageEnhance.Sharpness(pil_img)
    pil_img = enhancer.enhance(1.5)  # Reduced from 2.0
    
    # Convert back to OpenCV format
    img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
    
    # 4. Convert to grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # 5. Apply Gaussian blur to reduce noise
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    
    # 6. Enhanced adaptive thresholding
    thresh = cv2.adaptiveThreshold(
        blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
        cv2.THRESH_BINARY, 11, 2
    )
    
    # 7. Morphological operations to clean text
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (2, 1))
    thresh = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)
    
    return thresh, gray

def clean_extracted_text(text):
    """
    Clean and filter extracted text to remove noise and duplicates.
    """
    if not text:
        return ""
    
    # Split into lines and clean each line
    lines = text.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Remove excessive whitespace
        line = ' '.join(line.split())
        
        # Skip very short lines (likely noise)
        if len(line.strip()) < 3:
            continue
            
        # Skip lines with too many special characters (noise)
        special_char_ratio = sum(1 for c in line if not c.isalnum() and c != ' ') / len(line) if line else 0
        if special_char_ratio > 0.5:
            continue
            
        # Skip lines that are mostly numbers but not PIN codes
        if line.isdigit() and len(line) != 6:
            continue
            
        # Skip common OCR noise patterns
        noise_patterns = [
            r'^[^\w\s]+$',  # Only special characters
            r'^[a-zA-Z]{1,2}$',  # Single or double isolated letters
            r'^\d{1,2}$',  # Single or double isolated numbers
            r'^[\.\-_]+$',  # Only dots, dashes, underscores
        ]
        
        is_noise = any(re.match(pattern, line.strip()) for pattern in noise_patterns)
        if is_noise:
            continue
            
        cleaned_lines.append(line.strip())
    
    # Remove duplicates while preserving order
    seen = set()
    unique_lines = []
    for line in cleaned_lines:
        if line.lower() not in seen:
            seen.add(line.lower())
            unique_lines.append(line)
    
    return '\n'.join(unique_lines)

def find_pincode_enhanced(text):
    """Enhanced PIN code detection with better filtering."""
    if not text:
        return None
        
    # Clean the text first
    text = re.sub(r'[^\w\s]', ' ', text)  # Replace special chars with spaces
    text = ' '.join(text.split())  # Normalize whitespace
    
    # Enhanced patterns for PIN code detection
    patterns = [
        r'\b(\d{6})\b',  # Standard 6 digits
        r'PIN\s*:?\s*(\d{6})',  # PIN: 123456
        r'PINCODE\s*:?\s*(\d{6})',  # PINCODE: 123456
        r'POSTAL\s*CODE\s*:?\s*(\d{6})',  # POSTAL CODE: 123456
        r'(\d{3})\s*(\d{3})',  # 123 456 format
    ]
    
    found_pincodes = []
    
    for pattern in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            if match.groups():
                # Join all captured groups and remove spaces
                pincode = ''.join(match.groups()).replace(' ', '')
            else:
                pincode = match.group(0).replace(' ', '')
            
            # Validate it's exactly 6 digits
            if re.match(r'^\d{6}$', pincode):
                # Additional validation: Indian PIN codes start with 1-8
                if pincode[0] in '12345678':
                    found_pincodes.append(pincode)
    
    # Return the first valid PIN code found
    return found_pincodes[0] if found_pincodes else None

# This function shows the page with the new "queue" UI
@app.route("/staff/capture")
def capture_page():
    """Renders the live capture page for staff."""
    if 'loggedin' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    return render_template('live_capture.html')


@app.route('/staff/process_queue', methods=['POST'])
def process_queue():
    """
    Receives a list of images, performs OCR, and returns results.
    Handles duplicate detection to prevent processing the same content multiple times.
    """
    if 'loggedin' not in session or session['role'] != 'staff':
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        image_data_urls = data.get('images', [])
        results = []
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        staff_id = session.get('staff_id')
        login_time = session.get('login_time')
        
        if not staff_id or not login_time:
            return jsonify({'error': 'Session information missing'}), 400
        
        # Ensure schema is up-to-date
        ensure_parcel_columns()
        
        # Track processed content in this session to avoid duplicates
        processed_content = set()
        
        for index, image_data_url in enumerate(image_data_urls):
            # --- 1. Decode Image using Pillow (like the sample project) ---
            image_data = image_data_url.split(',')[1]
            decoded_image = base64.b64decode(image_data)
            
            # Use Pillow to open the image from bytes
            image = Image.open(io.BytesIO(decoded_image))
            
            # Convert the Pillow image to a NumPy array for EasyOCR
            img_np = np.array(image)

            # --- 2. Save the original captured image ---
            import time
            timestamp = int(time.time())
            image_filename = f"parcel_{staff_id}_{timestamp}_{index}.jpg"
            image_path = os.path.join('static', 'uploaded_parcels', image_filename)
            
            os.makedirs(os.path.dirname(image_path), exist_ok=True)
            # Save using Pillow for consistency
            image.save(image_path, "JPEG")

            # --- 3. Perform OCR on the RAW image (No preprocessing) ---
            # This is the key change: we trust EasyOCR with the unprocessed image.
            easyocr_results = reader.readtext(img_np, detail=0, paragraph=True)
            
            # Combine results and clean them
            raw_text = "\n".join(easyocr_results)
            full_text = clean_extracted_text(raw_text) # Your cleaning function is still useful!
            
            # --- 4. Check for duplicate content ---
            # Create a normalized version of the text for comparison
            normalized_text = ' '.join(full_text.lower().split()) if full_text else ""
            
            # Check if this content already exists in the current session
            cursor.execute("""
                SELECT parcel_id FROM Parcel 
                WHERE staff_id = %s AND upload_time >= %s AND extracted_address = %s
                LIMIT 1
            """, (staff_id, login_time, full_text.strip()))
            
            existing_duplicate = cursor.fetchone()
            
            # Also check in current batch
            is_duplicate_in_batch = normalized_text in processed_content and normalized_text != ""
            
            if existing_duplicate or is_duplicate_in_batch:
                # Mark as duplicate
                result = {
                    'status': 'Duplicate',
                    'message': 'Duplicate content detected. This postal item has already been processed.',
                    'full_text': full_text.strip() if full_text.strip() else 'Duplicate item',
                    'has_extracted_text': bool(raw_text.strip()),
                    'parcel_id': None,
                    'existing_parcel_id': existing_duplicate['parcel_id'] if existing_duplicate else None
                }
                results.append(result)
                continue
            
            # Add to processed content set
            if normalized_text:
                processed_content.add(normalized_text)
            
            # --- 5. Enhanced PIN code detection ---
            pin_code = find_pincode_enhanced(full_text)
            
            # --- 6. Determine status and prepare result ---
            if pin_code:
                status = 'Processed'
                result = {
                    'status': 'Success',
                    'pin_code': pin_code,
                    'full_text': full_text.strip() if full_text.strip() else 'PIN code extracted successfully.',
                    'has_extracted_text': bool(raw_text.strip())
                }
            else:
                status = 'Failed'
                result = {
                    'status': 'Error',
                    'message': 'No valid 6-digit PIN code could be identified.',
                    'full_text': full_text.strip() if full_text.strip() else 'No readable text found.',
                    'has_extracted_text': bool(raw_text.strip())
                }
            
            # --- 7. Insert into database ---
            try:
                # Check if any text was extracted from OCR (regardless of PIN detection)
                # This allows manual PIN entry when text exists but no valid PIN was auto-detected
                has_text = bool(raw_text.strip())  # Use raw OCR results to determine if any text was found
                
                # Store the cleaned extracted text as address for bin content display
                extracted_address = full_text.strip() if full_text.strip() else ""
                
                cursor.execute(
                    "INSERT INTO Parcel (image_path, status, staff_id, has_extracted_text, extracted_address) VALUES (%s, %s, %s, %s, %s)",
                    (image_path, status, staff_id, has_text, extracted_address)
                )
                parcel_id = cursor.lastrowid
                result['parcel_id'] = parcel_id
                conn.commit()
            except mysql.connector.Error as db_err:
                result['db_error'] = f"Database error: {str(db_err)}"
                result['parcel_id'] = None
                print(f"Database error for image {index}: {db_err}")
            results.append(result)

        cursor.close()
        conn.close()
        
        # Reverse the results to show newest items first (descending order)
        results.reverse()
        
        return jsonify({'results': results})
    except Exception as e:
        # Add more detailed error logging for debugging
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'An unexpected server error occurred.', 'details': str(e)}), 500
    
# Add a new route for manual PIN code entry
@app.route('/staff/update_pincode', methods=['POST'])
def update_pincode():
    """
    Updates a parcel with a manually entered PIN code or moves it to the Error Bin.
    Accepts a 6-digit PIN to mark as 'Processed' or the text 'error' to sort into the Error Bin.
    """
    if 'loggedin' not in session or session['role'] != 'staff':
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        parcel_id = data.get('parcel_id')
        manual_input = data.get('pincode', '').strip().lower()
        staff_id = session.get('staff_id')

        if not all([parcel_id, manual_input, staff_id]):
            return jsonify({'error': 'Missing required data: parcel_id, pincode, or staff_id'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # --- Verify Parcel ---
        cursor.execute("SELECT * FROM Parcel WHERE parcel_id = %s AND staff_id = %s", (parcel_id, staff_id))
        parcel = cursor.fetchone()
        if not parcel:
            cursor.close(); conn.close()
            return jsonify({'error': 'Parcel not found or access denied'}), 404

        # --- Check if already sorted ---
        cursor.execute("SELECT sort_id FROM sorted_item WHERE parcel_id = %s", (parcel_id,))
        if cursor.fetchone():
            cursor.close(); conn.close()
            return jsonify({'error': 'This parcel has already been sorted'}), 400

        # --- Handle "error" input ---
        if manual_input == 'error':
            error_bin_id = get_or_create_error_bin(staff_id, cursor, conn)
            cursor.execute("""
                INSERT INTO sorted_item (parcel_id, staff_id, bin_id, sorted_time)
                VALUES (%s, %s, %s, NOW())
            """, (parcel_id, staff_id, error_bin_id))
            
            # Also update parcel status to 'Failed' for clarity
            cursor.execute("UPDATE Parcel SET status = 'Failed' WHERE parcel_id = %s", (parcel_id,))
            
            conn.commit()
            cursor.close(); conn.close()
            return jsonify({
                'success': True,
                'moved_to_error_bin': True,
                'parcel_id': parcel_id,
                'message': 'Parcel moved to Error Bin.'
            })

        # --- Handle PIN code input ---
        # Validate PIN code format (6 digits)
        if not re.match(r'^\d{6}$', manual_input):
            cursor.close(); conn.close()
            return jsonify({'error': 'Invalid input. Please enter a 6-digit PIN code or the word "error".'}), 400
        
        # Update the parcel status to 'Processed'
        cursor.execute("UPDATE Parcel SET status = 'Processed' WHERE parcel_id = %s", (parcel_id,))
        conn.commit()
        cursor.close(); conn.close()
        
        return jsonify({
            'success': True, 
            'pincode': manual_input,
            'parcel_id': parcel_id,
            'moved_to_error_bin': False,
            'message': 'PIN code accepted. Parcel is ready for sorting.'
        })
        
    except Exception as e:
        # Log the full error for debugging
        traceback.print_exc()
        return jsonify({'error': f'An unexpected server error occurred: {str(e)}'}), 500

@app.route('/staff/get_unsorted_parcels', methods=['GET'])
def get_unsorted_parcels():
    """
    Get unsorted parcels for the current staff member from the current session
    to restore the capture queue.
    """
    if 'loggedin' not in session or session['role'] != 'staff':
        return jsonify({'error': 'Authentication required'}), 401

    try:
        staff_id = session.get('staff_id')
        login_time = session.get('login_time') # Get login time to filter parcels

        if not staff_id or not login_time:
            return jsonify({'error': 'Session information missing'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get all parcels that are processed but not yet sorted from the CURRENT session
        cursor.execute("""
            SELECT p.parcel_id, p.status, p.extracted_address, p.upload_time
            FROM Parcel p
            LEFT JOIN sorted_item si ON p.parcel_id = si.parcel_id
            WHERE p.staff_id = %s 
            AND si.parcel_id IS NULL
            AND p.status = 'Processed'
            AND p.upload_time >= %s
            ORDER BY p.upload_time ASC
        """, (staff_id, login_time))
        
        unsorted_parcels = cursor.fetchall()
        
        # Also get failed parcels with text from the CURRENT session (for manual PIN entry)
        cursor.execute("""
            SELECT p.parcel_id, p.status, p.extracted_address, p.upload_time, p.has_extracted_text
            FROM Parcel p
            LEFT JOIN sorted_item si ON p.parcel_id = si.parcel_id
            WHERE p.staff_id = %s 
            AND si.parcel_id IS NULL
            AND p.status = 'Failed'
            AND p.has_extracted_text = 1
            AND p.upload_time >= %s
            ORDER BY p.upload_time ASC
        """, (staff_id, login_time))
        
        failed_with_text = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'processed_parcels': unsorted_parcels,
            'failed_with_text': failed_with_text
        })
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/staff/sort_parcel', methods=['POST'])
def sort_parcel():
    """Sorts a processed parcel into the corresponding bin based on PIN code."""
    if 'loggedin' not in session or session['role'] != 'staff':
        return jsonify({'error': 'Authentication required'}), 401

    try:
        data = request.get_json()
        parcel_id = data.get('parcel_id')
        pin_code = data.get('pin_code')
        
        staff_id = session.get('staff_id')
        if not staff_id:
            return jsonify({'error': 'Staff ID not found in session'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Verify the parcel exists and belongs to this staff member
        cursor.execute("""
            SELECT parcel_id, status, staff_id 
            FROM Parcel 
            WHERE parcel_id = %s AND staff_id = %s
        """, (parcel_id, staff_id))
        parcel = cursor.fetchone()
        
        if not parcel:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Parcel not found or access denied'}), 404
        
        # 2. Check if parcel is processed (has PIN code)
        if parcel['status'] != 'Processed':
            cursor.close()
            conn.close()
            return jsonify({'error': 'Cannot sort unprocessed parcel. PIN code is required.'}), 400
        
        # 3. Check if parcel is already sorted
        cursor.execute("SELECT sort_id FROM sorted_item WHERE parcel_id = %s", (parcel_id,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Parcel has already been sorted'}), 400
        
        # 4. Find the corresponding bin for this PIN code and staff member
        cursor.execute("""
            SELECT bin_id, bin_name 
            FROM Bin 
            WHERE pin = %s AND staff_id = %s
        """, (int(pin_code), staff_id))
        bin_match = cursor.fetchone()
        
        if not bin_match:
            # Automatically move to Error Bin instead of returning error
            error_bin_id = get_or_create_error_bin(staff_id, cursor, conn)
            cursor.execute("""
                INSERT INTO sorted_item (parcel_id, staff_id, bin_id, sorted_time)
                VALUES (%s, %s, %s, NOW())
            """, (parcel_id, staff_id, error_bin_id))
            conn.commit()
            cursor.close(); conn.close()
            return jsonify({
                'success': True,
                'parcel_id': parcel_id,
                'bin_name': 'Error Bin',
                'bin_id': error_bin_id,
                'pin_code': pin_code,
                'error_bin': True,
                'note': f'No matching bin for PIN {pin_code}; moved to Error Bin.'
            })
        
        # 5. Insert into sorted_item table (normal path)
        cursor.execute("""
            INSERT INTO sorted_item (parcel_id, staff_id, bin_id, sorted_time)
            VALUES (%s, %s, %s, NOW())
        """, (parcel_id, staff_id, bin_match['bin_id']))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'parcel_id': parcel_id,
            'bin_name': bin_match['bin_name'],
            'bin_id': bin_match['bin_id'],
            'pin_code': pin_code
        })
        
    except mysql.connector.Error as db_err:
        return jsonify({'error': f'Database error: {str(db_err)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/staff/sort_all_parcels', methods=['POST'])
def sort_all_parcels():
    """Sort all unsorted parcels in batch from the current session."""
    if 'loggedin' not in session or session['role'] != 'staff':
        return jsonify({'error': 'Authentication required'}), 401

    try:
        staff_id = session.get('staff_id')
        login_time = session.get('login_time')
        if not staff_id or not login_time:
            return jsonify({'error': 'Session information missing'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # MODIFIED QUERY: Also select the image_path
        cursor.execute("""
            SELECT p.parcel_id, p.extracted_address, p.status, p.image_path 
            FROM Parcel p
            LEFT JOIN sorted_item si ON p.parcel_id = si.parcel_id
            WHERE p.staff_id = %s 
            AND si.parcel_id IS NULL
            AND p.upload_time >= %s
            AND p.status = 'Processed'
        """, (staff_id, login_time))
        
        unsorted_parcels = cursor.fetchall()
        
        sorted_count = 0
        error_count = 0
        sorted_details = []
        error_details = []
        
        error_bin_id = get_or_create_error_bin(staff_id, cursor, conn)

        for parcel in unsorted_parcels:
            parcel_id = parcel['parcel_id']
            address_text = parcel['extracted_address']
            pin_code = find_pincode_enhanced(address_text)
            
            if pin_code:
                cursor.execute("SELECT bin_id, bin_name FROM Bin WHERE pin = %s AND staff_id = %s", (int(pin_code), staff_id))
                bin_match = cursor.fetchone()
                
                if bin_match:
                    cursor.execute("INSERT INTO sorted_item (parcel_id, staff_id, bin_id, sorted_time) VALUES (%s, %s, %s, NOW())", (parcel_id, staff_id, bin_match['bin_id']))
                    sorted_count += 1
                    # MODIFIED DICTIONARY: Add the image_path to the result
                    sorted_details.append({
                        'parcel_id': parcel_id,
                        'pin_code': pin_code,
                        'bin_name': bin_match['bin_name'],
                        'image_path': parcel['image_path'].replace(os.sep, '/') # <-- KEY ADDITION
                    })
                else:
                    cursor.execute("INSERT INTO sorted_item (parcel_id, staff_id, bin_id, sorted_time) VALUES (%s, %s, %s, NOW())", (parcel_id, staff_id, error_bin_id))
                    error_count += 1
                    error_details.append({
                        'parcel_id': parcel_id, 
                        'pin_code': pin_code, 
                        'error': f'No bin for PIN {pin_code}', 
                        'image_path': parcel['image_path'].replace(os.sep, '/') # <-- KEY ADDITION
                    })
            else:
                cursor.execute("INSERT INTO sorted_item (parcel_id, staff_id, bin_id, sorted_time) VALUES (%s, %s, %s, NOW())", (parcel_id, staff_id, error_bin_id))
                error_count += 1
                error_details.append({
                    'parcel_id': parcel_id, 
                    'pin_code': None, 
                    'error': 'No PIN found', 
                    'image_path': parcel['image_path'] # <-- KEY ADDITION
                })
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'sorted_count': sorted_count,
            'error_count': error_count,
            'sorted_details': sorted_details,
            'error_details': error_details
        })
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route("/staff/sorted_items")
def view_sorted_items():
    """View all sorted items for the current staff member."""
    if 'loggedin' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    staff_id = session.get('staff_id')
    if not staff_id:
        flash('Staff ID not found in session. Please login again.', 'danger')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get all sorted items for this staff member with parcel and bin details
        cursor.execute("""
            SELECT 
                si.sort_id,
                si.parcel_id,
                si.sorted_time,
                p.image_path,
                p.upload_time,
                b.bin_name,
                b.pin
            FROM sorted_item si
            JOIN Parcel p ON si.parcel_id = p.parcel_id
            JOIN Bin b ON si.bin_id = b.bin_id
            WHERE si.staff_id = %s
            ORDER BY si.sorted_time DESC
        """, (staff_id,))
        
        sorted_items = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('sorted_items.html', 
                             sorted_items=sorted_items, 
                             username=session['username'])
        
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect(url_for('staff_dashboard'))
    except Exception as e:
        flash(f"Error: {e}", 'danger')
        return redirect(url_for('staff_dashboard'))

@app.route("/staff/bins", methods=['GET', 'POST'])
def view_bins():
    """
    Handles viewing the bin list (GET) and creating a new bin (POST).
    Accessible to staff. Bins are staff-specific.
    """
    if 'loggedin' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    staff_id = session.get('staff_id')

    if not staff_id:
        flash('Staff ID not found in session. Please login again.', 'danger')
        return redirect(url_for('login'))

    # Ensure a single persistent Error Bin exists (pin=0)
    cursor.execute("SELECT bin_id FROM Bin WHERE staff_id = %s AND bin_name = 'Error Bin'", (staff_id,))
    eb = cursor.fetchone()
    if not eb:
        cursor.execute("INSERT INTO Bin (bin_name, pin, staff_id) VALUES ('Error Bin', 0, %s)", (staff_id,))
        conn.commit()
        error_bin_id = cursor.lastrowid
    else:
        # eb may be dict or tuple depending on cursor config
        error_bin_id = eb['bin_id'] if isinstance(eb, dict) else eb[0]

    # --- HANDLE POST REQUEST (Creating a new bin) ---
    if request.method == 'POST':
        bin_name = request.form['bin_name'].strip()
        pin_code = request.form['pin_code'].strip()

        # Prevent creating another Error Bin manually
        if bin_name.lower() == 'error bin' or pin_code == '0':
            flash('Cannot create or modify the reserved Error Bin.', 'danger')
        else:
            validation_errors = []
            if not re.fullmatch(r'\d{6}', pin_code):
                validation_errors.append('PIN code must be exactly 6 digits.')
            elif not pin_code.startswith('673'):
                validation_errors.append('PIN code must start with "673".')
            bin_name_pattern = r'^bin\s+(\d{6})$'
            bin_name_match = re.match(bin_name_pattern, bin_name.lower())
            if not bin_name_match:
                validation_errors.append('Bin name must be in format "bin XXXXXX" (e.g., "bin 673303").')
            else:
                bin_number = bin_name_match.group(1)
                if bin_number != pin_code:
                    validation_errors.append(f'Bin name number "{bin_number}" must match PIN code "{pin_code}".')
            if validation_errors:
                for error in validation_errors:
                    flash(error, 'danger')
            else:
                try:
                    cursor.execute(
                        "INSERT INTO Bin (bin_name, pin, staff_id) VALUES (%s, %s, %s)",
                        (bin_name, int(pin_code), staff_id)
                    )
                    conn.commit()
                    flash(f"Bin '{bin_name}' created successfully!", 'success')
                except mysql.connector.Error as err:
                    if err.errno == 1062:
                        flash('A bin with this name or PIN code already exists for your account.', 'danger')
                    else:
                        flash(f"Database error: {err}", 'danger')

    # --- HANDLE GET REQUEST (Displaying the bin list - STAFF SPECIFIC) ---
    cursor.execute("SELECT * FROM Bin WHERE staff_id = %s AND bin_name <> 'Error Bin' ORDER BY bin_name", (staff_id,))
    bin_list = cursor.fetchall()
    cursor.close(); conn.close()
    return render_template('view_bins.html', bin_list=bin_list, error_bin_id=error_bin_id, username=session['username'])

@app.route('/staff/bin/pdf/<int:bin_id>')
def download_bin_pdf(bin_id):
    """
    Generates and serves a PDF report of a bin's contents
    FROM THE CURRENT LOGIN SESSION ONLY.
    """
    if 'loggedin' not in session or session['role'] != 'staff':
        return "Access Denied", 403
    
    staff_id = session.get('staff_id')
    # Get the login time to filter results for the current session
    login_time = session.get('login_time')

    if not staff_id or not login_time:
        flash('Session information is missing. Please log in again.', 'danger')
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Get Bin Info (and verify ownership)
        cursor.execute("SELECT * FROM Bin WHERE bin_id = %s AND staff_id = %s", (bin_id, staff_id))
        bin_info = cursor.fetchone()
        if not bin_info:
            return "Bin not found or access denied.", 404

        # 2. Get Bin Contents (MODIFIED QUERY)
        # This query now filters items sorted since the user logged in.
        cursor.execute("""
            SELECT si.parcel_id, p.extracted_address, p.upload_time, si.sorted_time
            FROM sorted_item si
            JOIN Parcel p ON si.parcel_id = p.parcel_id
            WHERE si.bin_id = %s 
            AND si.staff_id = %s 
            AND si.sorted_time >= %s
            ORDER BY si.sorted_time DESC
        """, (bin_id, staff_id, login_time))
        bin_contents = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        # 3. Render the HTML template for the PDF
        generation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html_string = render_template(
            'bin_pdf_template.html',
            bin_info=bin_info,
            bin_contents=bin_contents, # This will be an empty list if there are no items
            generation_time=generation_time
        )
        
        # 4. Generate the PDF using WeasyPrint
        base_url = request.url_root
        pdf = HTML(string=html_string, base_url=base_url).write_pdf()
        
        # 5. Create the HTTP response to send the file to the user
        filename = f"bin_{bin_info['pin']}_contents_session.pdf"
        response = Response(pdf, mimetype='application/pdf')
        response.headers['Content-Disposition'] = f'inline; filename={filename}'
        
        return response

    except Exception as e:
        traceback.print_exc()
        return f"An error occurred: {e}", 500

@app.route("/staff/history")
def view_sorted_history():
    """Renders a page showing all items sorted by the staff in the current session."""
    if 'loggedin' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    staff_id = session.get('staff_id')
    login_time = session.get('login_time')

    if not staff_id or not login_time:
        flash('Session information is missing. Please log in again.', 'danger')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # This query joins the three tables to get all the necessary details
        # for items sorted by the current staff member in the current session.
        cursor.execute("""
            SELECT 
                si.sort_id,
                si.parcel_id,
                si.sorted_time,
                p.image_path,
                p.upload_time,
                b.bin_name,
                b.pin
            FROM sorted_item si
            JOIN Parcel p ON si.parcel_id = p.parcel_id
            JOIN Bin b ON si.bin_id = b.bin_id
            WHERE si.staff_id = %s AND si.sorted_time >= %s
            ORDER BY si.sorted_time DESC
        """, (staff_id, login_time))
        
        sorted_items = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template(
            'staff_history.html', 
            sorted_items=sorted_items, 
            username=session['username']
        )
        
    except Exception as e:
        traceback.print_exc()
        flash(f"A database error occurred: {e}", 'danger')
        return redirect(url_for('staff_dashboard'))

@app.route("/staff/bins/remove/<int:bin_id>", methods=['POST'])
def remove_bin(bin_id):
    """Handles removing a bin. Staff can only remove their own bins (not Error Bin)."""
    if 'loggedin' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    staff_id = session.get('staff_id')
    if not staff_id:
        flash('Staff ID not found in session. Please login again.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection(); cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT bin_id, bin_name FROM Bin WHERE bin_id = %s AND staff_id = %s", (bin_id, staff_id))
        row = cursor.fetchone()
        if not row:
            flash('Bin not found or you do not have permission to remove it.', 'danger')
        elif row['bin_name'] == 'Error Bin':
            flash('Error Bin is permanent and cannot be removed.', 'danger')
        else:
            cursor.execute("DELETE FROM Bin WHERE bin_id = %s AND staff_id = %s", (bin_id, staff_id))
            if cursor.rowcount > 0:
                conn.commit(); flash('Bin removed successfully.', 'success')
            else:
                flash('Failed to remove bin.', 'danger')
    except mysql.connector.Error as err:
        if err.errno == 1451:
            flash('Cannot remove this bin because it has sorted items linked to it.', 'danger')
        else:
            flash(f"Database error: {err}", 'danger')
    finally:
        if conn.is_connected(): cursor.close(); conn.close()
    return redirect(url_for('view_bins'))


@app.route("/staff/bins/remove_all", methods=['POST'])
def remove_all_bins():
    """Remove all user-created bins except the permanent Error Bin."""
    if 'loggedin' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    staff_id = session.get('staff_id')
    if not staff_id:
        flash('Staff ID not found in session. Please login again.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("DELETE FROM Bin WHERE staff_id = %s AND bin_name <> 'Error Bin'", (staff_id,))
        deleted = cursor.rowcount
        conn.commit()
        if deleted > 0:
            flash(f'Removed {deleted} bin(s). Error Bin retained.', 'success')
        else:
            flash('No removable bins found.', 'info')
    except mysql.connector.Error as err:
        if err.errno == 1451:
            flash('Some bins could not be removed due to linked sorted items.', 'danger')
        else:
            flash(f"Database error: {err}", 'danger')
    finally:
        if conn.is_connected(): cursor.close(); conn.close()
    return redirect(url_for('view_bins'))

def ensure_parcel_columns():
    """Ensure required columns exist in Parcel table (idempotent)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Check and add has_extracted_text
        cursor.execute("SHOW COLUMNS FROM Parcel LIKE 'has_extracted_text'")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE Parcel ADD COLUMN has_extracted_text TINYINT(1) DEFAULT 0 AFTER staff_id")
        # Check and add extracted_address
        cursor.execute("SHOW COLUMNS FROM Parcel LIKE 'extracted_address'")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE Parcel ADD COLUMN extracted_address TEXT AFTER has_extracted_text")
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        # Silent fail; insertion will raise proper error later
        print(f"[ensure_parcel_columns] Warning: {e}")

@app.route('/staff/bin_contents_fragment/<int:bin_id>')
def bin_contents_fragment(bin_id):
    """Return HTML fragment for bin contents (used inside modal)."""
    if 'loggedin' not in session or session['role'] != 'staff':
        return jsonify({'error': 'Authentication required'}), 401
    staff_id = session.get('staff_id')
    if not staff_id:
        return jsonify({'error': 'Staff ID missing'}), 400
    login_time = session.get('login_time')  # Session-based filter
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT bin_id, bin_name, pin FROM Bin WHERE bin_id = %s AND staff_id = %s", (bin_id, staff_id))
        bin_info = cursor.fetchone()
        if not bin_info:
            cursor.close(); conn.close()
            return jsonify({'error': 'Bin not found'}), 404
        if login_time:
            cursor.execute("""
                SELECT si.sort_id, si.parcel_id, si.sorted_time, p.extracted_address, p.upload_time, b.pin
                FROM sorted_item si
                JOIN Parcel p ON si.parcel_id = p.parcel_id
                JOIN Bin b ON si.bin_id = b.bin_id
                WHERE si.bin_id = %s AND si.staff_id = %s AND si.sorted_time >= %s
                ORDER BY si.sorted_time DESC
            """, (bin_id, staff_id, login_time))
        else:
            cursor.execute("""
                SELECT si.sort_id, si.parcel_id, si.sorted_time, p.extracted_address, p.upload_time, b.pin
                FROM sorted_item si
                JOIN Parcel p ON si.parcel_id = p.parcel_id
                JOIN Bin b ON si.bin_id = b.bin_id
                WHERE si.bin_id = %s AND si.staff_id = %s
                ORDER BY si.sorted_time DESC
            """, (bin_id, staff_id))
        bin_contents = cursor.fetchall()
        cursor.close(); conn.close()
        return render_template('bin_contents_fragment.html', bin_info=bin_info, bin_contents=bin_contents)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Helper: ensure an Error Bin exists for a staff member
def get_or_create_error_bin(staff_id, cursor, conn):
    """Return bin_id for the staff member's Error Bin (create if missing)."""
    cursor.execute("SELECT bin_id FROM Bin WHERE bin_name = %s AND staff_id = %s", ('Error Bin', staff_id))
    row = cursor.fetchone()
    if row:
        return row['bin_id'] if isinstance(row, dict) else row[0]
    # Create with pin=0 (reserved). Assumes no validation here.
    cursor.execute("INSERT INTO Bin (bin_name, pin, staff_id) VALUES (%s, %s, %s)", ('Error Bin', 0, staff_id))
    conn.commit()
    return cursor.lastrowid

if __name__ == '__main__':
    app.run(host='0.0.0.0',port='5000',debug=True)