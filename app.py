# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash, g
import json
import os
import secrets # For generating SECRET_KEY
from datetime import datetime
import pytz # For timezone handling
import requests # For Google Apps Script integration
import csv # For reading CSV for dashboard (locally) - Note: not actively used for dashboard now, mostly GS
from dotenv import load_dotenv # For loading environment variables from .env locally
from flask_moment import Moment # For displaying human-readable times in templates
from functools import wraps # For decorators
from werkzeug.security import generate_password_hash, check_password_hash # For password hashing
import time # For retries

# --- Configuration ---
load_dotenv() # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))
if app.secret_key == secrets.token_hex(16):
    print("WARNING: FLASK_SECRET_KEY environment variable not set. Using a temporary random key. Set a persistent FLASK_SECRET_KEY for production!")

moment = Moment(app)

# Define Ghana timezone
GHANA_TIMEZONE = pytz.timezone('Africa/Accra')

# --- New: Define a higher default timeout for Google Sheets requests ---
GOOGLE_SHEETS_REQUEST_TIMEOUT = 15 # Increased from 5 to 15 seconds
MAX_RETRIES = 3
RETRY_DELAY = 1 # seconds

def get_ghana_time():
    """Returns the current datetime in Ghana's timezone."""
    return datetime.now(GHANA_TIMEZONE)

@app.before_request
def before_request():
    """Sets the current Ghana time in the global 'g' object for template access."""
    g.current_time = get_ghana_time()

# In-memory attendance records (primarily for local debugging, ephemeral on Render)
in_memory_attendance_records = []

# Google Apps Script Web App URL from environment variables
GOOGLE_SHEET_WEB_APP_URL = os.getenv('GOOGLE_SHEET_WEB_APP_URL', "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE")
if GOOGLE_SHEET_WEB_APP_URL == "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
    print("WARNING: GOOGLE_SHEET_WEB_APP_URL not set in environment variables or .env. Google Sheets integration will not work!")

def send_to_google_sheets(data):
    """Sends data (attendance, session config, access logs) to Google Sheets via Web App."""
    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL
    if not google_sheet_url or google_sheet_url == "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        print("Google Apps Script URL not configured. Skipping Google Sheets upload.")
        return False
    try:
        # --- MODIFIED: Increased timeout for POST requests ---
        response = requests.post(google_sheet_url, json=data, timeout=GOOGLE_SHEETS_REQUEST_TIMEOUT)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

        try:
            response_json = response.json()
            print(f"Sent to Google Sheets: {data}. GAS Response (JSON): {json.dumps(response_json)}")
            if response_json.get('result') == 'error':
                print(f"Apps Script reported an internal error: {response_json.get('message')}")
                return False

        except json.JSONDecodeError:
            print(f"ERROR: Google Apps Script returned non-JSON response! Status: {response.status_code}, Content: {response.text[:500]}...")
            return False

        return True

    except requests.exceptions.RequestException as e:
        print(f"ERROR sending to Google Sheets (RequestException): {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred when sending to Google Sheets: {e}")
        return False

def get_session_details_from_gs(session_id):
    """
    Fetches the status and full configuration (lat, lon, radius) of a specific session from Google Sheets.
    Returns a dictionary with status (e.g., 'active', 'paused', 'closed', 'not_found', 'error'),
    message, and session details if available.
    """
    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL
    if not google_sheet_url or google_sheet_url == "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        print("Google Apps Script URL not configured. Cannot get session status.")
        return {'status': 'error', 'message': 'Google Sheets URL not configured.'}

    params = {'action': 'getSessionDetails', 'session_id': session_id}
    last_error = None

    for attempt in range(MAX_RETRIES):
        try:
            print(f"Attempt {attempt + 1}/{MAX_RETRIES}: Fetching session details for '{session_id}' with params: {params}")
            # --- MODIFIED: Increased timeout for GET requests ---
            response = requests.get(google_sheet_url, params=params, timeout=GOOGLE_SHEETS_REQUEST_TIMEOUT)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

            response_json = response.json()
            print(f"Raw response from get_session_details_from_gs for '{session_id}': {response_json}")

            if response_json.get('result') == 'success' and response_json.get('session'):
                session_data = response_json.get('session')
                # Ensure required fields are present; default if not
                return {
                    'status': session_data.get('status', 'not_found'), # 'active', 'paused', 'closed', 'not_found'
                    'message': response_json.get('message', 'Session details fetched.'),
                    'session_id': session_data.get('session_id'),
                    'latitude': float(session_data.get('latitude', 0.0)),
                    'longitude': float(session_data.get('longitude', 0.0)),
                    'radius': int(session_data.get('radius', 0))
                }
            else:
                # If result is not success or session details are missing (e.g., session not found)
                return {
                    'status': response_json.get('status', 'not_found'), # GAS should ideally return 'not_found' if session_id is valid but not in sheet
                    'message': response_json.get('message', 'Session not found or an unknown error occurred.')
                }

        except requests.exceptions.RequestException as e:
            last_error = e
            print(f"Error getting session details from GS for {session_id} (RequestException) on attempt {attempt + 1}: {e}")
            if attempt < MAX_RETRIES - 1:
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
        except json.JSONDecodeError as e:
            last_error = e
            print(f"Error decoding session details JSON for {session_id} on attempt {attempt + 1}: {e}. Raw: {response.text[:500]}")
            # No retry for JSON decode errors, as it suggests a consistent issue with the script's output
            break
        except Exception as e:
            last_error = e
            print(f"An unexpected error occurred while fetching session details for {session_id} on attempt {attempt + 1}: {e}")
            # No retry for general exceptions, as it suggests a consistent issue
            break

    # If all retries fail or a non-retryable error occurs
    return {'status': 'error', 'message': f'Failed to retrieve session details after {MAX_RETRIES} attempts. Last error: {last_error}'}


# These functions are assumed to be in attendance_utils.py and qr_generator.py
# Make sure these files exist in the same directory as app.py
try:
    from attendance_utils import calculate_distance, save_attendance_local
    from qr_generator import generate_qr_code
except ImportError as e:
    print(f"ERROR: Could not import utility functions: {e}")
    print("Please ensure attendance_utils.py and qr_generator.py are in the same directory.")
    # Define dummy functions to prevent app from crashing for now
    def calculate_distance(lat1, lon1, lat2, lon2): return 1000000 # Always out of range
    def save_attendance_local(data): print("Dummy save_attendance_local called.")
    def generate_qr_code(data, filename_prefix="qr_code"): return f"qr_codes/{filename_prefix}_dummy_qr.png"


def get_lecturer_config_defaults():
    """Retrieves initial/default lecturer configuration from environment variables."""
    config = {
        'latitude': float(os.getenv('LECTURER_LATITUDE', 0.0)),
        'longitude': float(os.getenv('LECTURER_LONGITUDE', 0.0)),
        'radius': int(os.getenv('LECTURER_RADIUS', 0)),
        'session_id': os.getenv('LECTURER_SESSION_ID', ''),
        'status': 'unknown' # Default status for in-memory config
    }
    return config

# This dictionary stores the *last configured* session details from the /lecturer_config page.
# It's used to pre-fill the form and provide context for the QR generator.
current_lecturer_config_in_memory = get_lecturer_config_defaults()

# Dashboard login password hashing
DASHBOARD_PASSWORD_HASH = generate_password_hash(os.getenv('DASHBOARD_PASSWORD', 'default_dashboard_password'))
if os.getenv('DASHBOARD_PASSWORD') is None:
    print("WARNING: DASHBOARD_PASSWORD environment variable not set. Using a default password. Set a strong password for production!")

def lecturer_login_required(f):
    """Decorator to ensure only logged-in lecturers can access a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in') or session.get('user_role') != 'lecturer':
            flash("Unauthorized access. Lecturer privileges required.", "error")
            return redirect(url_for('dashboard_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Renders the landing page."""
    return render_template('index.html')

@app.route('/dashboard_login', methods=['GET', 'POST'])
def dashboard_login():
    """Handles lecturer login for the dashboard."""
    if request.method == 'POST':
        password = request.form.get('password')

        if not os.getenv('DASHBOARD_PASSWORD'):
            flash("Dashboard password not set in server configuration. Access denied.", "error")
            return render_template('dashboard_login.html')

        if check_password_hash(DASHBOARD_PASSWORD_HASH, password):
            session['logged_in'] = True
            session['user_role'] = 'lecturer'
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid Password.", "error")
            return render_template('dashboard_login.html')

    return render_template('dashboard_login.html')

@app.route('/dashboard')
@lecturer_login_required
def dashboard():
    """Renders the lecturer dashboard, fetching session and attendance summaries from Google Sheets."""
    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL

    all_sessions = []
    if google_sheet_url and google_sheet_url != "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        try:
            # Fetch all sessions for display in the "All Created Attendances" section
            all_sessions_response = requests.get(google_sheet_url, params={'action': 'getAllSessions'}, timeout=GOOGLE_SHEETS_REQUEST_TIMEOUT)
            all_sessions_response.raise_for_status()
            all_sessions_data = all_sessions_response.json()
            all_sessions = all_sessions_data.get('sessions', [])
            # Sort sessions by creation date, most recent first
            all_sessions.sort(key=lambda x: x.get('created_at', ''), reverse=True)

            print(f"All sessions fetched: {all_sessions}")

        except requests.exceptions.RequestException as e:
            flash(f"Error fetching all sessions from Google Sheet: {e}", "error")
            print(f"Error fetching all sessions from Google Sheet: {e}")
        except json.JSONDecodeError as e:
            flash(f"Error decoding JSON for all sessions: {e}", "error")
            print(f"Error decoding JSON for all sessions: {e}. Raw response: {all_sessions_response.text[:500]}...")
    else:
        flash("Google Sheet URL not configured. Cannot list sessions.", "info")

    # Get summary for the *currently active* session if one is configured in memory
    current_conf = current_lecturer_config_in_memory
    session_id_filter = current_conf.get('session_id') # This is the active one from config page

    attendance_summary = {'totalScans': 0, 'presentCount': 0, 'absentCount': 0}
    portal_access_counts = {'totalAccesses': 0, 'uniqueStudents': 0}

    # Only fetch summary if there's an active session configured in memory AND GS URL is set
    if session_id_filter and google_sheet_url and google_sheet_url != "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        try:
            summary_params = {'action': 'getSummary', 'session_id': session_id_filter}
            print(f"Attempting to fetch attendance summary for active session with params: {summary_params}")
            response = requests.get(google_sheet_url, params=summary_params, timeout=GOOGLE_SHEETS_REQUEST_TIMEOUT)
            response.raise_for_status()
            summary_data = response.json()
            print(f"Successfully fetched attendance summary for active session: {summary_data}")

            attendance_summary['totalScans'] = summary_data.get('totalScans', 0)
            attendance_summary['presentCount'] = summary_data.get('presentCount', 0)
            attendance_summary['absentCount'] = summary_data.get('absentCount', 0)

        except requests.exceptions.RequestException as e:
            flash(f"Error fetching attendance summary for active session from Google Sheet: {e}", "error")
            print(f"Error fetching attendance summary for active session from Google Sheet: {e}")
            attendance_summary = {'totalScans': 0, 'presentCount': 0, 'absentCount': 0, 'message': f"Data unavailable: {e}"}
        except json.JSONDecodeError as e:
            flash(f"Error decoding JSON from Google Sheet summary (active session): {e}", "error")
            print(f"Error decoding JSON from Google Sheet summary (active session): {e}. Raw response: {response.text[:500]}...")
            attendance_summary = {'totalScans': 0, 'presentCount': 0, 'absentCount': 0, 'message': f"Data unavailable: {e}"}

        try:
            access_params = {'action': 'getAccessCounts', 'session_id': session_id_filter}
            print(f"Attempting to fetch portal access counts for active session with params: {access_params}")
            access_response = requests.get(google_sheet_url, params=access_params, timeout=GOOGLE_SHEETS_REQUEST_TIMEOUT)
            access_response.raise_for_status()
            access_data = access_response.json()
            print(f"Successfully fetched portal access counts for active session: {access_data}")

            portal_access_counts['totalAccesses'] = access_data.get('totalAccesses', 0)
            portal_access_counts['uniqueStudents'] = access_data.get('uniqueStudents', 0)

        except requests.exceptions.RequestException as e:
            flash(f"Error fetching portal access counts for active session from Google Sheet: {e}", "error")
            print(f"Error fetching portal access counts for active session from Google Sheet: {e}")
            portal_access_counts = {'totalAccesses': 0, 'uniqueStudents': 0, 'message': f"Data unavailable: {e}"}
        except json.JSONDecodeError as e:
            flash(f"Error decoding JSON from Google Sheet access counts (active session): {e}", "error")
            print(f"Error decoding JSON from Google Sheet access counts (active session): {e}. Raw response: {access_response.text[:500]}...")
            portal_access_counts = {'totalAccesses': 0, 'uniqueStudents': 0, 'message': f"Data unavailable: {e}"}
    else:
        # If no session is configured in memory, or GS URL is bad, default to no summary
        print("No active session configured or Google Sheet URL not set. Skipping summary fetch.")

    attendance_data = [] # Placeholder if you were to display detailed attendance locally

    return render_template('dashboard.html',
                            current_session=current_conf,
                            total_scans_session=attendance_summary['totalScans'],
                            present_count=attendance_summary['presentCount'],
                            absent_count=attendance_summary['absentCount'],
                            attendance_data=attendance_data,
                            total_portal_accesses=portal_access_counts['totalAccesses'],
                            unique_portal_students=portal_access_counts['uniqueStudents'],
                            all_sessions=all_sessions # Pass all sessions to the template
                            )

@app.route('/logout')
def logout():
    """Logs the lecturer out."""
    session.pop('logged_in', None)
    session.pop('user_role', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('dashboard_login'))

@app.route('/lecturer_config', methods=['GET', 'POST'])
@lecturer_login_required
def lecturer_config_route():
    """Handles lecturer configuring a new attendance session or updating an existing one."""
    global current_lecturer_config_in_memory
    if request.method == 'POST':
        try:
            latitude = float(request.form['latitude'])
            longitude = float(request.form['longitude'])
            radius = int(request.form['radius'])
            session_id = request.form['session_id'].strip()

            if not (-90 <= latitude <= 90):
                raise ValueError("Latitude must be between -90 and 90.")
            if not (-180 <= longitude <= 180):
                raise ValueError("Longitude must be between -180 and 180.")
            if not (radius > 0):
                raise ValueError("Radius must be a positive number.")

            if not session_id:
                # If session_id is not provided, generate a new one
                now_ghana = get_ghana_time()
                session_id = f"SESSION_{now_ghana.strftime('%Y%m%d_%H%M%S')}"

            # Update in-memory config - this keeps track of the *last configured* session
            current_lecturer_config_in_memory['latitude'] = latitude
            current_lecturer_config_in_memory['longitude'] = longitude
            current_lecturer_config_in_memory['radius'] = radius
            current_lecturer_config_in_memory['session_id'] = session_id
            current_lecturer_config_in_memory['status'] = 'active' # Set status to active in memory immediately

            # Send to Google Sheets to create/update session status in the "Sessions" sheet
            session_data = {
                'action': 'createOrUpdateSession',
                'session_id': session_id,
                'latitude': latitude,
                'longitude': longitude,
                'radius': radius,
                'status': 'active' # Always set to active when lecturer configures/reconfigures
            }
            sheets_sent = send_to_google_sheets(session_data)
            if not sheets_sent:
                flash("Configuration saved, but could not sync session state to Google Sheets. Check server logs.", "warning")
            else:
                flash("Configuration saved successfully! This session is now active and recorded.", "success")

            # Log this config change as an access event (optional, for tracking lecturer actions)
            log_data = {
                'action': 'logAccess',
                'session_id': session_id,
                'student_id': 'LECTURER_CONFIG_UPDATE'
            }
            send_to_google_sheets(log_data)

            return redirect(url_for('qr_generator_page'))

        except ValueError as e:
            flash(f"Invalid input: {e}", "error")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")

    return render_template('lecturer_config.html', config=current_lecturer_config_in_memory)

@app.route('/qr_generator', methods=['GET', 'POST'])
@lecturer_login_required
def qr_generator_page():
    config_for_qr = current_lecturer_config_in_memory
    qr_code_path = None
    generated_link = None
    student_id_display = None

    session_id_to_use = config_for_qr.get('session_id')

    # If no session ID is even configured in memory, prompt the user
    if not session_id_to_use:
        flash("Please configure an active session on the Lecturer Config page first to generate a QR code.", "error")
        # Ensure we pass the (empty) config for the template to render correctly
        return render_template('qr_generator.html', current_session=config_for_qr, qr_code_path=None, generated_link=None, student_id_display=None)

    # Get the real-time status and full details of the configured session from Google Sheet
    session_details_from_gs = get_session_details_from_gs(session_id_to_use)
    session_status = session_details_from_gs.get('status')

    # If the session is not 'active' (could be 'paused', 'closed', 'not_found', or 'error')
    if session_status != 'active':
        flash_message = f"The configured session '{session_id_to_use}' is currently '{session_status}'. "
        if session_status == 'not_found':
            flash_message += "It might not have been recorded in the system, or has been deleted."
        elif session_status == 'error':
            flash_message += f"There was an error fetching its status: {session_details_from_gs.get('message', 'Unknown error')}. Please check network or try again."
        else: # paused, closed
            flash_message += "Please make it active on the Dashboard or Lecturer Config page before generating a QR code."

        flash(flash_message, "warning")

        # Merge fetched details into config_for_qr for display in the 'Active Session Details' box
        config_for_qr.update({
            'status': session_status,
            'latitude': session_details_from_gs.get('latitude', config_for_qr.get('latitude')),
            'longitude': session_details_from_gs.get('longitude', config_for_qr.get('longitude')),
            'radius': session_details_from_gs.get('radius', config_for_qr.get('radius'))
        })

        return render_template('qr_generator.html',
                               current_session=config_for_qr, # Pass the updated config
                               qr_code_path=None,
                               generated_link=None,
                               student_id_display=None)

    # If we reach here, the session is 'active' as per Google Sheets.
    # We should update config_for_qr with the latest details from GS for display accuracy
    config_for_qr.update({
        'status': session_status,
        'latitude': session_details_from_gs.get('latitude'),
        'longitude': session_details_from_gs.get('longitude'),
        'radius': session_details_from_gs.get('radius')
    })


    if request.method == 'POST':
        student_id_qr = request.form.get('student_id_qr')
        if not student_id_qr:
            flash("Please enter a Student ID to generate the QR code.", "error")
            return render_template('qr_generator.html',
                                    current_session=config_for_qr,
                                    qr_code_path=None,
                                    generated_link=None,
                                    student_id_display=None)

        base_url = request.url_root.rstrip('/')
        # QR code should point to the check-in page with just the session ID
        checkin_url_for_qr = f"{base_url}/checkin/{session_id_to_use}"

        qr_code_filename_base = f"{session_id_to_use.strip()}_{student_id_qr.strip()}"

        try:
            qr_code_path_relative = generate_qr_code(checkin_url_for_qr, filename_prefix=qr_code_filename_base)
            qr_code_path = url_for('static', filename=qr_code_path_relative)
            generated_link = checkin_url_for_qr
            student_id_display = student_id_qr

            flash(f"QR Code generated for Student: {student_id_qr}, Session: {session_id_to_use}!", "success")

        except Exception as e:
            flash(f"Error generating QR code: {e}", "error")
            print(f"Error generating QR code for {student_id_qr}: {e}")
            qr_code_path = None
            generated_link = None
            student_id_display = None

    # This part handles the initial GET request to load the page
    # or re-renders after a POST submission.
    return render_template('qr_generator.html',
                            current_session=config_for_qr,
                            qr_code_path=qr_code_path,
                            generated_link=generated_link,
                            student_id_display=student_id_display)


@app.route('/checkin/<session_id_from_qr>') # Route now expects the session_id
def student_checkin(session_id_from_qr): # Parameter name changed
    """
    Renders the student check-in page. The QR code encodes the session_id,
    and students will enter their details on this page.
    """
    message_override = None
    hide_geolocation = False
    lecturer_conf_for_template = {} # To hold the specific session's config

    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL
    if not google_sheet_url or google_sheet_url == "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        message_override = "System error: Google Sheet URL not configured. Cannot verify session or attendance."
        hide_geolocation = True
    else:
        # Fetch the full session details from Google Sheets using the session_id_from_qr
        session_details_response = get_session_details_from_gs(session_id_from_qr)
        session_status = session_details_response.get('status')
        session_message = session_details_response.get('message', 'Unknown error.')

        if session_status == 'active':
            # Populate lecturer_conf_for_template with the active session's details from GS
            # These values are needed by the client-side JS for geolocation check
            lecturer_conf_for_template = {
                'session_id': session_id_from_qr,
                'latitude': session_details_response.get('latitude'),
                'longitude': session_details_response.get('longitude'),
                'radius': session_details_response.get('radius')
            }

            # Log initial portal access for this session (before student enters ID)
            access_data = {
                'action': 'logAccess',
                'session_id': session_id_from_qr,
                'student_id': 'PORTAL_ACCESS_INITIAL' # Generic ID for initial page load
            }
            try:
                # --- MODIFIED: Increased timeout for logging initial access ---
                requests.post(google_sheet_url, json=access_data, timeout=GOOGLE_SHEETS_REQUEST_TIMEOUT)
                print(f"Logged initial portal access for session {session_id_from_qr} to Google Sheet.")
            except requests.exceptions.RequestException as e:
                print(f"Error logging initial portal access for session {session_id_from_qr} to Google Sheet: {e}")

        elif session_status == 'error':
            message_override = f"System error: Could not verify session status. {session_message}. Please try again later."
            hide_geolocation = True
        elif session_status == 'not_found':
            message_override = f"Attendance session '{session_id_from_qr}' not found or never started. Please contact your lecturer."
            hide_geolocation = True
        else: # Covers 'paused' and 'closed'
            message_override = f"Attendance for session '{session_id_from_qr}' is currently {session_status}. You cannot submit attendance at this time."
            hide_geolocation = True

    return render_template('checkin.html',
                            session_id=session_id_from_qr, # Pass the session_id from the URL to the template
                            message_override=message_override,
                            hide_geolocation=hide_geolocation,
                            lecturer_conf=lecturer_conf_for_template) # Pass session details for JS


@app.route('/submit_attendance', methods=['POST'])
def submit_attendance():
    """Receives attendance submission from student, performs validation, and logs to Google Sheets."""
    data = request.get_json()
    student_id = data.get('student_id')
    student_name = data.get('student_name')
    student_index = data.get('student_index')
    student_lat = data.get('latitude')
    student_lon = data.get('longitude')
    session_id = data.get('session_id') # CRITICAL: Get session_id from the form submission

    if not all([student_id, student_name, student_index, session_id]):
        return jsonify(status="error", message="Missing required student information or session ID.")

    # Fetch the actual lecturer configuration for THIS specific session from Google Sheets
    lecturer_conf = {} # Initialize empty
    session_details_response = get_session_details_from_gs(session_id)

    if session_details_response.get('status') == 'active':
        lecturer_conf['latitude'] = session_details_response.get('latitude')
        lecturer_conf['longitude'] = session_details_response.get('longitude')
        lecturer_conf['radius'] = session_details_response.get('radius')
        # Also ensure to pass these values for logging/calculation purposes if needed below
        lecturer_conf['session_id'] = session_id # Ensure session_id is consistent
    else:
        # If session is not active or not found, return an error immediately
        return jsonify(status="error", message=f"Attendance for session '{session_id}' is currently {session_details_response.get('status', 'unknown')}. Cannot record attendance.")

    if not lecturer_conf or 'latitude' not in lecturer_conf or lecturer_conf.get('radius') is None:
        return jsonify(status="error", message="Classroom location or radius not properly configured for this session. Attendance cannot be recorded.")

    class_lat = lecturer_conf.get('latitude')
    class_lon = lecturer_conf.get('longitude')
    allowed_radius = lecturer_conf.get('radius')

    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL
    if google_sheet_url and google_sheet_url != "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        # Check for duplicate submission for THIS student in THIS active session
        check_params = {
            'action': 'checkStudentAttendance',
            'student_id': student_id,
            'session_id': session_id # Use the session_id from the student's submission
        }
        try:
            print(f"Checking for duplicate attendance for student {student_id}, session {session_id}...")
            # --- MODIFIED: Increased timeout for checkStudentAttendance ---
            check_response = requests.get(google_sheet_url, params=check_params, timeout=GOOGLE_SHEETS_REQUEST_TIMEOUT)
            check_response.raise_for_status()
            check_data = check_response.json()

            print(f"Apps Script checkStudentAttendance response: {check_data}")

            if check_data.get('hasAttended'):
                print(f"Student {student_id} has already attended session {session_id}.")
                return jsonify(status="error", message="You have already submitted attendance for this session.")
            else:
                print(f"Student {student_id} has not yet attended session {session_id}. Proceeding with submission.")

        except requests.exceptions.RequestException as e:
            print(f"ERROR checking duplicate attendance (RequestException): {e}. This error will not prevent submission for now.")
            pass # Allow submission if GS check fails, but log the error. You might want to be stricter.
        except json.JSONDecodeError as e:
            print(f"ERROR decoding JSON from attendance check: {e}. Raw response: {check_response.text[:500]}...")
            pass # Allow submission if JSON is malformed, but log.
        except Exception as e:
            print(f"An unexpected error occurred during duplicate attendance check: {e}. This error will not prevent submission for now.")
            pass
    else:
        print("Google Apps Script URL not configured for duplicate attendance check. Skipping check.")


    now_ghana = get_ghana_time()
    timestamp = now_ghana.strftime("%Y-%m-%d %H:%M:%S")

    status = "Absent"
    message = ""
    distance = None

    if student_lat is None or student_lon is None:
        status = "Absent (Geolocation Failed)"
        message = "Could not get your location. Please ensure location services are enabled and permitted."
    elif class_lat is None or class_lon is None or allowed_radius is None:
        status = "Absent (Session Config Error)"
        message = "Classroom location or radius not properly configured for this session."
    else:
        distance = calculate_distance(student_lat, student_lon, class_lat, class_lon)
        if distance <= allowed_radius:
            status = "Present"
            message = "You are marked present! Welcome."
        else:
            status = f"Absent (Out of Range)"
            message = f"You are {distance:.2f} meters away."

    record_data = {
        'action': 'submitAttendance',
        'Timestamp': timestamp,
        'Student_ID': student_id,
        'Student_Name': student_name,
        'Student_Index': student_index,
        'Latitude': student_lat,
        'Longitude': student_lon,
        'Status': status,
        'Distance': f"{distance:.2f}" if distance is not None and distance != float('inf') else 'N/A',
        'Session_ID': session_id, # Use the session_id from the student's submission
        'Class_Lat': class_lat,
        'Class_Lon': class_lon,
        'Radius_Meters': allowed_radius
    }

    save_attendance_local(record_data) # Keep for local testing if needed, though ephemeral on Render
    in_memory_attendance_records.append(record_data) # Ephemeral on Render
    sheets_sent = send_to_google_sheets(record_data) # Persistent in Google Sheets

    if not sheets_sent:
        message += " (Note: Could not sync to Google Sheets, check server logs for details)."

    return jsonify(status="success" if "Present" in status else "error", message=message)

@app.route('/update_session_status', methods=['POST'])
@lecturer_login_required
def update_session_status():
    """Allows lecturer to change a session's status (active, paused, closed)."""
    session_id = request.form.get('session_id')
    new_status = request.form.get('status') # 'active', 'paused', 'closed'

    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL
    if not google_sheet_url or google_sheet_url == "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        flash("Google Sheet URL not configured. Cannot update session status.", "error")
        return redirect(url_for('dashboard'))

    if not session_id or not new_status:
        flash("Missing session ID or new status.", "error")
        return redirect(url_for('dashboard'))

    try:
        update_data = {
            'action': 'updateSessionStatus',
            'session_id': session_id,
            'status': new_status
        }
        # --- MODIFIED: Increased timeout for updateSessionStatus ---
        response = requests.post(google_sheet_url, json=update_data, timeout=GOOGLE_SHEETS_REQUEST_TIMEOUT)
        response.raise_for_status()
        response_json = response.json()

        if response_json.get('result') == 'success':
            flash(f"Session '{session_id}' status updated to '{new_status}' successfully!", "success")
            # If the session being updated is the one in lecturer_config_in_memory, update its status too
            if current_lecturer_config_in_memory.get('session_id') == session_id:
                current_lecturer_config_in_memory['status'] = new_status # Update local in-memory status
        else:
            flash(f"Failed to update session status: {response_json.get('message', 'Unknown error')}", "error")
            print(f"Failed to update session status for {session_id} to {new_status}. GAS Response: {response_json}")

    except requests.exceptions.RequestException as e:
        flash(f"Network error updating session status: {e}", "error")
        print(f"Network error updating session status for {session_id}: {e}")
    except json.JSONDecodeError as e:
        flash(f"Error decoding response updating session status: {e}", "error")
        print(f"Error decoding JSON updating session status for {session_id}: {e}. Raw: {response.text[:500]}")
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", "error")
        print(f"An unexpected error occurred updating session status for {session_id}: {e}")

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    # Create a 'qr_codes' directory if it doesn't exist
    if not os.path.exists('static/qr_codes'):
        os.makedirs('static/qr_codes')
    app.run(debug=True)