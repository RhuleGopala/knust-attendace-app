# attendance_utils.py
from geopy.distance import geodesic
import csv
import os

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculates the distance between two geographical points in meters."""
    coords1 = (lat1, lon1)
    coords2 = (lat2, lon2)
    return geodesic(coords1, coords2).meters

# This function will now accept a dictionary of attendance data
def save_attendance_local(record_data):
    """
    Saves attendance record to a local CSV file.
    This file will NOT persist on services like Heroku/Render after restarts.
    """
    # Changed from 'attendance_log.csv' to 'attendance_records.csv' for consistency
    # with the previous discussions, although it's a local file name.
    csv_file_path = 'attendance_records.csv' 
    file_exists = os.path.isfile(csv_file_path)
    
    # Define headers based on the keys in record_data, ensuring order.
    # IMPORTANT: All fields that will be written to the CSV MUST be in this list.
    fieldnames = [
        'action',          # <-- ADDED THIS FIELD to resolve the ValueError
        'Timestamp',
        'Student_ID',
        'Student_Name',    # Added Student_Name
        'Student_Index',   # Added Student_Index
        'Latitude',
        'Longitude',
        'Status',
        'Distance',
        'Session_ID',
        'Class_Lat',
        'Class_Lon',
        'Radius_Meters'
    ]

    # Ensure all fieldnames exist in record_data, add N/A if not
    # This loop is crucial because DictWriter expects all fieldnames to be present as keys in the dict
    for field in fieldnames:
        if field not in record_data:
            record_data[field] = 'N/A'

    # Changed file name to csv_file_path variable
    with open(csv_file_path, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader() # Write header only if file is new

        writer.writerow(record_data)
        print(f"Logged to {csv_file_path}: {record_data.get('Student_ID', 'N/A')} - {record_data.get('Status', 'N/A')}")