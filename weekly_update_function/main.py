"""
main.py — Weekly Cloud Function for Rewarding Users in SII

This script is triggered as a scheduled Google Cloud Function each week.
It performs the following tasks:

1️⃣ Pulls all users from Firestore.
2️⃣ Sorts them by their correct prediction count.
3️⃣ Assigns coin rewards based on weekly performance (top 3 + participation bonuses).
4️⃣ Adds bonus coins for users who submitted all 10 predictions.
5️⃣ Resets each user's predictionCount to 10 for the new week.

⚠️ Required filename: 'main.py' is necessary for GCP function entry.
🚀 Triggered weekly to drive coin economy & maintain user engagement.

Note:
- Uses Firestore's Increment() operation for atomic coin updates.
- Can be enhanced to support BTTS or injury/discipline mechanics later.
"""


from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import firebase_admin
from google.cloud import firestore

# Initialize Firebase using Application Default Credentials (ADC)
# In Cloud Functions / Cloud Run, ADC is provided automatically.
# Locally, use `GOOGLE_APPLICATION_CREDENTIALS` env var pointing to a keyfile (never committed),
# or `gcloud auth application-default login`.
load_dotenv()
PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")
if not firebase_admin._apps:
    firebase_admin.initialize_app()
db = firestore.Client(project=PROJECT_ID)

def weekly_update(request):  # Cloud Function needs 'request' parameter
    print("🚀 Starting Weekly Update Script...")

    users_ref = db.collection("users").stream()
    users_data = []

    # Step 1️⃣: Collect user data & ensure they have required fields
    for user in users_ref:
        user_data = user.to_dict()
        user_id = user.id  

        # Ensure all necessary fields exist
        user_data.setdefault("correctPredictions", 0)
        user_data.setdefault("coins", 0)
        user_data.setdefault("predictionCount", 10)  

        users_data.append({
            "id": user_id,
            "username": user_data.get("username", "Unknown"),
            "correctPredictions": user_data["correctPredictions"],
            "coins": user_data["coins"],
            "predictionCount": user_data["predictionCount"]
        })

    # Step 2️⃣: Sort users by correct predictions (descending order)
    users_data.sort(key=lambda x: x["correctPredictions"], reverse=True)
    
    # Step 3️⃣: Determine Coin Rewards Based on Rank
    total_users = len(users_data)
    half_point = total_users // 2

    for idx, user in enumerate(users_data):
        reward = 15  # Default for bottom half

        if idx == 0:
            reward = 50  # 🏆 1st Place
        elif idx == 1:
            reward = 40  # 🥈 2nd Place
        elif idx == 2:
            reward = 30  # 🥉 3rd Place
        elif idx < half_point:
            reward = 25  # 📈 Top half reward

        # Step 4️⃣: Check if user made all 10 predictions → Bonus +10 Coins
        if user["predictionCount"] == 0:
            reward += 10  # Bonus for full participation

        # Step 5️⃣: Update Firestore (add coins & reset `predictionCount`)
        user_ref = db.collection("users").document(user["id"])
        user_ref.update({
            "coins": firestore.Increment(reward),
            "predictionCount": 10  # Reset for new week
        })

        print(f"✅ {user['username']} received {reward} coins! (Now has: {user['coins'] + reward})")

    print("🎯 Weekly Update Script Complete!")
    return "Weekly update completed successfully.", 200
