# print_user_coins.py
from google.cloud import firestore

# Assumes GOOGLE_APPLICATION_CREDENTIALS env var is set
# or you've authenticated with: gcloud auth application-default login
db = firestore.Client()

def main():
    users_ref = db.collection("users")
    docs = users_ref.stream()

    print(f"{'User ID':<30} {'Username':<20} {'Coin Balance':>12}")
    print("-" * 70)

    for doc in docs:
        data = doc.to_dict() or {}
        username = data.get("username") or data.get("managerName") or "Unknown"
        coins = data.get("coinBalance", data.get("coins", 0))
        print(f"{doc.id:<30} {username:<20} {coins:>12}")

if __name__ == "__main__":
    main()