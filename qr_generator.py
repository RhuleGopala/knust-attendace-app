# qr_generator.py
import qrcode
import os
from datetime import datetime

# Ensure this directory exists relative to where your app.py runs
QR_CODE_DIR = 'static/qr_codes'
if not os.path.exists(QR_CODE_DIR):
    os.makedirs(QR_CODE_DIR)

def generate_qr_code(data: str, filename_prefix: str = "qr_code") -> str:
    """
    Generates a QR code for the given data and saves it to a file.

    Args:
        data (str): The data to encode in the QR code (e.g., a URL).
        filename_prefix (str): A prefix for the filename. Defaults to "qr_code".

    Returns:
        str: The relative path to the generated QR code image (e.g., 'qr_codes/my_qr_code.png').
    """
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Create a unique filename using the prefix and timestamp
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        filename = f"{filename_prefix}_{timestamp}.png"
        filepath = os.path.join(QR_CODE_DIR, filename)

        img.save(filepath)
        print(f"QR code saved to: {filepath}")
        return os.path.join('qr_codes', filename) # Return path relative to static/
    except Exception as e:
        print(f"Error in generate_qr_code: {e}")
        raise # Re-raise the exception to be caught by the Flask app