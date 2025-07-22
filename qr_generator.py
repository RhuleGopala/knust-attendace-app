import qrcode
import os
# from flask import url_for # No longer directly needed here as app.py handles url_for

# Directory where QR codes will be saved
# Note: This path is relative to the project root, where app.py is.
QR_CODE_DIR = 'static/qr_codes'

def generate_qr_code(data_string, student_id="unknown"):
    """
    Generates a QR code for the given data_string and saves it to a file.
    Returns the relative path to the QR code image within the static folder,
    suitable for Flask's url_for('static', filename=...)
    """
    # Ensure the directory exists
    # The full path needs to be created from the app's root directory.
    # app.py's __main__ block now ensures this directory exists.
    if not os.path.exists(QR_CODE_DIR):
        os.makedirs(QR_CODE_DIR)

    # Generate a unique filename for the QR code
    filename = f"{student_id}_qr.png"
    filepath = os.path.join(QR_CODE_DIR, filename)

    # Generate QR code
    img = qrcode.make(data_string)
    img.save(filepath)

    # Return the path relative to the static folder (e.g., 'qr_codes/S001_qr.png')
    # This is what Flask's url_for('static', filename=...) expects.
    return os.path.join(os.path.basename(QR_CODE_DIR), filename)