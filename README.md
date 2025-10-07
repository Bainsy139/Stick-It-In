# Stick It In (SII) – Web Edition (V3)

**Stick It In** is a browser-based football prediction game built with **Flask** and **Firebase Firestore**.  
It powers the 2025/26 private “Club Edition” season, where 20 managers compete through weekly predictions, coins, and a dynamic leaderboard.

---

## ⚙️ Features

- Predict real football match outcomes and earn points.
- Firestore integration for user data, predictions, and leaderboards.
- Automated weekly updates and admin tools.
- Marketplace and card mechanics (Red, Yellow, Injury, Physio, _Bribe the Ref_, and _Appeal the Decision_) with coin economy.
- Future expansion planned for social sharing and multi-league support.

---

## 🚀 Installation & Setup

> You’ll need **Python 3.10+** and **pip** installed before starting.

1. **Clone the repository**

   ```bash
   git clone https://github.com/Bainsy139/SII-web.git
   cd SII-web
   ```

2. **Set up a virtual environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Create your `.env` file**
   Use `.env.example` as a guide and add your local credentials and API keys.

4. **Run the app**
   ```bash
   python3 app.py
   ```
   The app will run on [http://localhost:5001](http://localhost:5001).

---

## 🧩 Tech Stack

- Python (Flask)
- Firebase / Firestore
- HTML, CSS, JavaScript
- Cloud Run (Deployment)
- Chart.js (for admin analytics)

---

## 🔒 Notes

- Secrets and API keys are **never committed** to this repo.
- `.env` is required locally; see `.env.example` for variable names.
- Cloud deployment uses environment variables managed in Google Cloud.
