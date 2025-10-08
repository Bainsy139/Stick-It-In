import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials
from google.cloud import firestore

# Load environment variables (for local dev)
load_dotenv()

# Use ADC (Application Default Credentials)
# In Cloud Functions or Cloud Run, ADC is provided automatically.
# Locally, use GOOGLE_APPLICATION_CREDENTIALS or gcloud auth application-default login.
if not firebase_admin._apps:
    firebase_admin.initialize_app()

db = firestore.Client(project=os.getenv("FIREBASE_PROJECT_ID"))

def increment_week_number(request):
    """Increment the current season week number in the Firestore state/seasonTracking document."""
    doc_ref = db.collection("state").document("seasonTracking")

    doc = doc_ref.get()
    if not doc.exists:
        return "seasonTracking document does not exist.", 404

    data = doc.to_dict()
    current_week = data.get("weekNumber", 0)
    new_week = current_week + 1

    # Update Firestore
    doc_ref.update({"weekNumber": new_week})

    # Log info for testing
    print(f"Week number updated: {current_week} → {new_week}")

    # Return readable message
    return f"Week number updated: {current_week} → {new_week}", 200

if __name__ == "__main__":
    print("⚠️  This automation script has not been tested against live Firestore. For demonstration only.")
