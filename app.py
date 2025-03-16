import os
import json
import requests
import xmltodict
from flask import Flask, request, jsonify
from flask_cors import CORS
from mongoengine import connect, Document, StringField
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor

# Load environment variables from .env file
load_dotenv()

# Initialize Flask application
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://127.0.0.1:5500"]}}, supports_credentials=True)

# Connect to MongoDB database
MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/phishing_db")
connect(host=MONGO_URI)

# Define MongoDB Model for storing phishing URLs
class PhishingURL(Document):
    url = StringField(required=True, unique=True)

# Retrieve API keys from environment variables
GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# API Endpoints
GOOGLE_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls"
PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.xml"

# Function to check if a URL is in the PhishTank database
def check_phish_tank(url):
    try:
        response = requests.get(PHISHTANK_FEED_URL)
        if response.status_code != 200:
            app.logger.error(f"PhishTank returned status {response.status_code}")
            return False
        
        data = xmltodict.parse(response.content)  # Convert XML response to dictionary
        if not data:
            app.logger.error("PhishTank response is empty or invalid.")
            return False
        
        phishing_sites = data.get("phishtank_submission_list", {}).get("submission", [])
        if isinstance(phishing_sites, list):
            return any(entry.get("url") == url for entry in phishing_sites)
        elif isinstance(phishing_sites, dict):
            return phishing_sites.get("url") == url
    except Exception as e:
        app.logger.error(f"Error checking PhishTank: {str(e)}")
    return False

# Function to check if a URL is flagged by Google Safe Browsing
def check_google_safe_browsing(url):
    request_body = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(GOOGLE_API_URL, json=request_body, headers={"Content-Type": "application/json"})
        response_data = response.json()
        return "matches" in response_data
    except requests.RequestException as e:
        app.logger.error(f"Error checking Google Safe Browsing: {str(e)}")
        return False

# Function to check if a URL is flagged by VirusTotal
def check_virus_total(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}
    try:
        # Submit URL to VirusTotal for analysis
        response = requests.post(VIRUSTOTAL_API_URL, headers=headers, data=data)
        response_data = response.json()
        analysis_id = response_data.get("data", {}).get("id", None)
        if not analysis_id:
            return False
        
        # Retrieve analysis report
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(analysis_url, headers=headers)
        report = response.json()
        
        stats = report.get("data", {}).get("attributes", {}).get("stats", {})
        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
            return True
        
        return False
    except requests.RequestException as e:
        app.logger.error(f"Error checking VirusTotal: {str(e)}")
        return False

# API Endpoint to check a given URL against multiple services
@app.route("/check-url", methods=["GET"])
def check_url():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    try:
        # Check if URL already exists in local MongoDB cache
        existing_phish = PhishingURL.objects(url=url).first()
        if existing_phish:
            app.logger.warning(f"⚠️ URL found in local database: {url}")
            return jsonify({"matches": True, "source": "local_db"})
        
        # Run phishing checks concurrently
        with ThreadPoolExecutor() as executor:
            future_phish_tank = executor.submit(check_phish_tank, url)
            future_google = executor.submit(check_google_safe_browsing, url)
            future_virus_total = executor.submit(check_virus_total, url)
            
            results = {
                "phish_tank": future_phish_tank.result(),
                "google_safe_browsing": future_google.result(),
                "virus_total": future_virus_total.result(),
            }
        
        # If any of the services detect phishing, store URL in MongoDB
        if any(results.values()):
            PhishingURL(url=url).save()
            return jsonify({"matches": True, "source": [k for k, v in results.items() if v]})
        
        return jsonify({"matches": False, "source": "clean"})
    except Exception as e:
        app.logger.error(f"❌ Error checking URL: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Start the Flask server
if __name__ == "__main__":
    PORT = int(os.getenv("PORT", 4500))
    app.run(host="0.0.0.0", port=PORT, debug=True)