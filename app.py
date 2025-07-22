# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash, g
import json
import os
import secrets # For generating SECRET_KEY
from datetime import datetime
import pytz # For timezone handling
import requests # For Google Apps Script integration
import csv # For reading CSV for dashboard (locally)
from dotenv import load_dotenv # For loading environment variables from .env locally
from flask_moment import Moment # For displaying human-readable times in templates
from functools import wraps # For decorators
from werkzeug.security import generate_password_hash, check_password_hash # For password hashing

# --- Configuration ---
load_dotenv() # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16)) 
if app.secret_key == secrets.token_hex(16):
    print("WARNING: FLASK_SECRET_KEY environment variable not set. Using a temporary random key. Set a persistent FLASK_SECRET_KEY for production!")

moment = Moment(app)

GHANA_TIMEZONE = pytz.timezone('Africa/Accra')

def get_ghana_time():
    return datetime.now(GHANA_TIMEZONE)

@app.before_request
def before_request():
    g.current_time = get_ghana_time()

in_memory_attendance_records = []

GOOGLE_SHEET_WEB_APP_URL = os.getenv('GOOGLE_SHEET_WEB_APP_URL', "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE")
if GOOGLE_SHEET_WEB_APP_URL == "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
    print("WARNING: GOOGLE_SHEET_WEB_APP_URL not set in environment variables or .env. Google Sheets integration will not work!")

def send_to_google_sheets(data):
    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL
    if not google_sheet_url or google_sheet_url == "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        print("Google Apps Script URL not configured. Skipping Google Sheets upload.")
        return False
    try:
        response = requests.post(google_sheet_url, json=data, timeout=10)
        response.raise_for_status()

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

# --- New Function to get session status from Google Sheet ---
def get_session_status_from_gs(session_id):
    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL
    if not google_sheet_url or google_sheet_url == "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        print("Google Apps Script URL not configured. Cannot get session status.")
        return {'status': 'error', 'message': 'Google Sheets URL not configured.'}
    try:
        params = {'action': 'getSessionStatus', 'session_id': session_id}
        response = requests.get(google_sheet_url, params=params, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error getting session status from GS: {e}")
        return {'status': 'error', 'message': f'Network error: {e}'}
    except json.JSONDecodeError as e:
        print(f"Error decoding session status JSON: {e}. Raw: {response.text}")
        return {'status': 'error', 'message': f'Invalid response from server: {e}'}


from attendance_utils import calculate_distance, save_attendance_local
from qr_generator import generate_qr_code

def get_lecturer_config():
    # This function now primarily retrieves initial values or defaults.
    # The 'active' session configuration is now primarily driven by Google Sheets.
    config = {
        'latitude': float(os.getenv('LECTURER_LATITUDE', 0.0)),
        'longitude': float(os.getenv('LECTURER_LONGITUDE', 0.0)),
        'radius': int(os.getenv('LECTURER_RADIUS', 0)),
        'session_id': os.getenv('LECTURER_SESSION_ID', '')
    }
    return config # Always return config, even if defaults are 0.0

# current_lecturer_config_in_memory will be updated by lecturer_config_route
# It holds the *last configured* session, which may or may not be 'active' in GS.
current_lecturer_config_in_memory = get_lecturer_config()

DASHBOARD_PASSWORD_HASH = generate_password_hash(os.getenv('DASHBOARD_PASSWORD', 'default_dashboard_password'))
if os.getenv('DASHBOARD_PASSWORD') is None:
    print("WARNING: DASHBOARD_PASSWORD environment variable not set. Using a default password. Set a strong password for production!")

def lecturer_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in') or session.get('user_role') != 'lecturer':
            flash("Unauthorized access. Lecturer privileges required.", "error")
            return redirect(url_for('dashboard_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard_login', methods=['GET', 'POST'])
def dashboard_login():
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
    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL

    all_sessions = []
    if google_sheet_url and google_sheet_url != "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        try:
            # Fetch all sessions for display in the "All Created Attendances" section
            all_sessions_response = requests.get(google_sheet_url, params={'action': 'getAllSessions'}, timeout=10)
            all_sessions_response.raise_for_status()
            all_sessions_data = all_sessions_response.json()
            all_sessions = all_sessions_data.get('sessions', [])
            # Sort sessions by creation date, most recent first (assuming 'created_at' is YYYY-MM-DD HH:MM:SS)
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

    # Now, try to get summary for the *currently active* session if one is configured.
    # The 'current_lecturer_config_in_memory' still holds the one that was set via /lecturer_config
    current_conf = current_lecturer_config_in_memory 
    session_id_filter = current_conf.get('session_id') # This is the active one from config page

    attendance_summary = {'totalScans': 0, 'presentCount': 0, 'absentCount': 0}
    portal_access_counts = {'totalAccesses': 0, 'uniqueStudents': 0}

    # Only fetch summary if there's an active session configured in memory
    if session_id_filter and google_sheet_url and google_sheet_url != "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        try:
            summary_params = {'action': 'getSummary', 'session_id': session_id_filter}
            print(f"Attempting to fetch attendance summary for active session with params: {summary_params}")
            response = requests.get(google_sheet_url, params=summary_params, timeout=10)
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
            access_response = requests.get(google_sheet_url, params=access_params, timeout=10)
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


    attendance_data = [] 

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
    session.pop('logged_in', None)
    session.pop('user_role', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('dashboard_login'))

@app.route('/lecturer_config', methods=['GET', 'POST'])
@lecturer_login_required
def lecturer_config_route():
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
                now_ghana = get_ghana_time()
                session_id = f"SESSION_{now_ghana.strftime('%Y%m%d_%H%M%S')}"

            # Update in-memory config - this keeps track of the *last configured* session
            current_lecturer_config_in_memory['latitude'] = latitude
            current_lecturer_config_in_memory['longitude'] = longitude
            current_lecturer_config_in_memory['radius'] = radius
            current_lecturer_config_in_memory['session_id'] = session_id

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
            
            # Log this config change as an access event too (optional, for tracking lecturer actions)
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

    # Check if there's an active session configured in memory
    session_status = None
    if config_for_qr.get('session_id'):
        session_status_response = get_session_status_from_gs(config_for_qr['session_id'])
        session_status = session_status_response.get('status')
        if session_status == 'closed' or session_status == 'paused':
            flash(f"Current configured session '{config_for_qr['session_id']}' is {session_status}. Please activate it or create a new one to generate QR codes.", "warning")
            config_for_qr['session_id'] = '' # Temporarily clear session_id for QR generation if not active

    if request.method == 'POST':
        student_id = request.form.get('student_id_qr')
        if student_id and config_for_qr and config_for_qr.get('session_id') and session_status == 'active': # Ensure session is active
            base_url = request.url_root.rstrip('/')
            checkin_url = f"{base_url}/checkin/{student_id}"

            qr_code_path_relative = generate_qr_code(checkin_url, student_id=student_id)
            qr_code_path = url_for('static', filename=qr_code_path_relative)

            generated_link = checkin_url
            student_id_display = student_id
            flash(f"QR Code and Link generated for Student: {student_id}!", "success")
        elif not config_for_qr.get('session_id'):
            flash("Please configure a session on the Lecturer Config page first.", "error")
        elif session_status != 'active':
            flash("Cannot generate QR code: Current session is not active.", "error")
        else:
            flash("Please enter a Student ID.", "error")

    return render_template('qr_generator.html',
                            current_session=config_for_qr,
                            qr_code_path=qr_code_path,
                            generated_link=generated_link,
                            student_id_display=student_id_display)

@app.route('/checkin/<student_id>')
def student_checkin(student_id):
    lecturer_conf = current_lecturer_config_in_memory # This is the last configured session

    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL
    
    # Check if a session ID is even configured for this system
    session_id_for_checkin = lecturer_conf.get('session_id')
    if not session_id_for_checkin:
        return render_template('checkin.html', student_id=student_id,
                               message_override="No attendance session is currently configured by the lecturer.",
                               hide_geolocation=True,
                               lecturer_conf={})

    # Get the real-time status of the configured session from Google Sheet
    session_status_response = get_session_status_from_gs(session_id_for_checkin)
    session_status = session_status_response.get('status')
    
    # Handle various session states before allowing check-in
    if session_status == 'error':
        return render_template('checkin.html', student_id=student_id,
                               message_override=f"System error: Could not verify session status. {session_status_response.get('message')}. Please try again later.",
                               hide_geolocation=True,
                               lecturer_conf={})
    elif session_status == 'not_found':
        return render_template('checkin.html', student_id=student_id,
                               message_override=f"Attendance session '{session_id_for_checkin}' not found or never started. Please contact your lecturer.",
                               hide_geolocation=True,
                               lecturer_conf={})
    elif session_status != 'active': # Covers 'paused' and 'closed'
        return render_template('checkin.html', student_id=student_id,
                               message_override=f"Attendance for session '{session_id_for_checkin}' is currently {session_status}. You cannot submit attendance at this time.",
                               hide_geolocation=True,
                               lecturer_conf={})

    # If session is active, log portal access and render the form
    if google_sheet_url and google_sheet_url != "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        access_data = {
            'action': 'logAccess', 
            'session_id': session_id_for_checkin,
            'student_id': student_id
        }
        try:
            requests.post(google_sheet_url, json=access_data, timeout=3) 
            print(f"Logged portal access for {student_id} to Google Sheet.")
        except requests.exceptions.RequestException as e:
            print(f"Error logging portal access for {student_id} to Google Sheet: {e}")
    
    return render_template('checkin.html', student_id=student_id, 
                           message_override=None, 
                           hide_geolocation=False,
                           lecturer_conf=lecturer_conf)


@app.route('/submit_attendance', methods=['POST'])
def submit_attendance():
    data = request.get_json()
    student_id = data.get('student_id')
    student_name = data.get('student_name')
    student_index = data.get('student_index')
    student_lat = data.get('latitude')
    student_lon = data.get('longitude')

    lecturer_conf = current_lecturer_config_in_memory # This is the last configured session

    if not lecturer_conf or 'latitude' not in lecturer_conf:
        return jsonify(status="error", message="No active session configured by lecturer. Attendance cannot be recorded.")

    class_lat = lecturer_conf.get('latitude')
    class_lon = lecturer_conf.get('longitude')
    allowed_radius = lecturer_conf.get('radius')
    session_id = lecturer_conf.get('session_id', 'N/A')

    # --- CRITICAL: Check session status from Google Sheet before processing attendance ---
    session_status_response = get_session_status_from_gs(session_id)
    session_status = session_status_response.get('status')

    if session_status == 'error':
        return jsonify(status="error", message=f"System error: Could not verify session status. {session_status_response.get('message')}")
    elif session_status == 'not_found':
         return jsonify(status="error", message=f"Attendance session '{session_id}' not found. Cannot record attendance.")
    elif session_status != 'active':
        return jsonify(status="error", message=f"Attendance for session '{session_id}' is currently {session_status}. You cannot submit attendance.")
    # --- END CRITICAL CHECK ---

    google_sheet_url = GOOGLE_SHEET_WEB_APP_URL
    if google_sheet_url and google_sheet_url != "YOUR_GOOGLE_APPS_SCRIPT_WEB_APP_URL_HERE":
        # Check for duplicate submission for THIS student in THIS active session
        check_params = {
            'action': 'checkStudentAttendance', 
            'student_id': student_id,
            'session_id': session_id
        }
        try:
            print(f"Checking for duplicate attendance for student {student_id}, session {session_id}...")
            check_response = requests.get(google_sheet_url, params=check_params, timeout=5)
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
        message = "Classroom location or radius not properly configured by lecturer."
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
        'Session_ID': session_id,
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
        response = requests.post(google_sheet_url, json=update_data, timeout=10)
        response.raise_for_status()
        response_json = response.json()

        if response_json.get('result') == 'success':
            flash(f"Session '{session_id}' status updated to '{new_status}' successfully!", "success")
        else:
            flash(f"Failed to update session status: {response_json.get('message', 'Unknown error')}", "error")
            print(f"Failed to update session status. Apps Script response: {response_json}")

    except requests.exceptions.RequestException as e:
        flash(f"Network error updating session status: {e}", "error")
        print(f"Network error updating session status: {e}")
    except json.JSONDecodeError as e:
        flash(f"Invalid response from Google Sheet when updating session status: {e}", "error")
        print(f"Invalid response from Google Sheet when updating session status: {e}. Raw: {response.text}")
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", "error")
        print(f"An unexpected error occurred when updating session status: {e}")

    return redirect(url_for('dashboard'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    qr_codes_dir = os.path.join(app.root_path, 'static', 'qr_codes')
    os.makedirs(qr_codes_dir, exist_ok=True)

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)