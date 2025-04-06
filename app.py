from flask import Flask, request, render_template, redirect, url_for, session, Response
from pymongo import MongoClient
import joblib
import datetime
from urllib.parse import unquote
from io import StringIO
import csv
from collections import Counter
import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Load ML model and vectorizer
model = joblib.load('model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

# MongoDB Atlas setup from environment
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client["honeypot"]
collection = db["logs"]

# Admin credentials (for demonstration purposes)
ADMIN_CREDENTIALS = {'username': 'admin', 'password': 'admin123'}

def predict_attack_type(input_data):
    X_vect = vectorizer.transform([input_data])
    return model.predict(X_vect)[0]
'''
def check_ip_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": os.getenv("VT_API_KEY")
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            reputation = data["data"]["attributes"].get("reputation", 0)
            malicious_votes = data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
            return {
                "reputation": reputation,
                "malicious_votes": malicious_votes
            }
    except Exception as e:
        print("VirusTotal API error:", e)
    return None
'''
def check_ip_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": os.getenv("VT_API_KEY")
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attributes = data["data"]["attributes"]
            reputation = attributes.get("reputation", 0)
            malicious_votes = attributes.get("total_votes", {}).get("malicious", 0)
            country = attributes.get("country", "Unknown")
            return {
                "reputation": reputation,
                "malicious_votes": malicious_votes,
                "country": country
            }
        else:
            print("VirusTotal API error:", response.status_code, response.text)
    except Exception as e:
        print("VirusTotal Exception:", e)
    return None

def log_request(ip, user_agent, input_data, prediction, source):
    vt_result = check_ip_virustotal(ip)

    log = {
        "input": input_data,
        "ip": ip,
        "user_agent": user_agent,
        "prediction": prediction,
        "source": source,
        "timestamp": datetime.datetime.now(),
        "vt_reputation": vt_result.get("reputation") if vt_result else None,
        "vt_malicious_votes": vt_result.get("malicious_votes") if vt_result else None
    }
    collection.insert_one(log)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        user_input = request.form.get("input", "")
        password = request.form.get("input2", "")
        combined_input = f"{user_input} | {password}"
        source = "POST"
    else:
        user_input = request.args.get("input", "")
        combined_input = user_input
        source = "GET"

    if combined_input.strip():
        ip = ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        user_agent = request.headers.get("User-Agent")
        prediction = predict_attack_type(combined_input)
        log_request(ip, user_agent, combined_input, prediction, source)

        if prediction != "benign":
            return render_template("error.html")

        return redirect(url_for("success"))

    return render_template("index.html")

@app.route("/success")
def success():
    return render_template("success.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == ADMIN_CREDENTIALS["username"] and password == ADMIN_CREDENTIALS["password"]:
            session["admin_logged_in"] = True
            return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))

    logs = list(collection.find().sort("timestamp", -1))
    attack_counts = Counter(log["prediction"] for log in logs)
    timeline_counts = Counter(
        log["timestamp"].strftime("%Y-%m-%d") for log in logs
    )

    return render_template("dashboard.html", logs=logs,
                           attack_counts=attack_counts,
                           timeline_counts=timeline_counts)

@app.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("index"))

@app.route("/delete_last")
def delete_last():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    last_log = collection.find_one(sort=[("timestamp", -1)])
    if last_log:
        collection.delete_one({"_id": last_log["_id"]})
    return redirect(url_for("dashboard"))

@app.route("/delete_all")
def delete_all():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))
    collection.delete_many({})
    return redirect(url_for("dashboard"))

@app.route("/export_csv")
def export_csv():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))

    logs = list(collection.find().sort("timestamp", -1))

    csv_file = StringIO()
    writer = csv.writer(csv_file)
    writer.writerow(["Timestamp", "IP", "User Agent", "Input", "Prediction", "Source", "VT Reputation", "VT Malicious Votes"])

    for log in logs:
        writer.writerow([
            log.get("timestamp"),
            log.get("ip"),
            log.get("user_agent"),
            log.get("input"),
            log.get("prediction"),
            log.get("source"),
            log.get("vt_reputation", "N/A"),
            log.get("vt_malicious_votes", "N/A")
        ])

    csv_file.seek(0)
    return Response(
        csv_file.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=honeypot_logs.csv"}
    )

if __name__ == "__main__":
    app.run(debug=True)