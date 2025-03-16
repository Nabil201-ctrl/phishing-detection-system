# SafeSurf - AI-Powered Phishing Detection System

![SafeSurf Logo](#)

SafeSurf is an AI-powered phishing detection system that helps users identify malicious URLs by checking them against multiple threat intelligence services, including Google Safe Browsing, VirusTotal, and PhishTank.

## Features
- **Real-Time Phishing Detection**: Check URLs in real-time against multiple threat databases.
- **Multi-Source Verification**: Uses Google Safe Browsing, VirusTotal, and PhishTank for comprehensive threat detection.
- **Local Caching**: Stores detected phishing URLs in a local MongoDB database for faster future lookups.
- **User-Friendly Interface**: Simple and intuitive web interface for analyzing URLs.
- **Concurrent Processing**: Utilizes multi-threading to perform checks concurrently for faster results.

## Technologies Used
- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Database**: MongoDB (via MongoEngine)
- **APIs**:
  - Google Safe Browsing API
  - VirusTotal API
  - PhishTank XML Feed
- **Other Libraries**:
  - `requests` for API calls
  - `xmltodict` for parsing PhishTank XML data
  - `dotenv` for environment variable management
  - `flask_cors` for handling CORS

## Setup Instructions

### Prerequisites
- **Python 3.8+**: Ensure Python is installed on your system.
- **MongoDB**: Install and run a MongoDB server locally or use a cloud instance.
- **API Keys**:
  - Google Safe Browsing API Key
  - VirusTotal API Key
  - (Optional) PhishTank API Key (if available)

### Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/safesurf.git
   cd safesurf
   ```
2. **Create a virtual environment and install dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. **Create a `.env` file** in the root directory and add your API keys:
   ```env
   MONGO_URI=mongodb://127.0.0.1:27017/phishing_db
   GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```
4. **Run the Flask backend:**
   ```bash
   python app.py
   ```
5. **Open `index.html` in your browser** to access the frontend.

## Usage

### Backend API
The backend provides a single endpoint for checking URLs:

- **Endpoint**: `/check-url`
- **Method**: `GET`
- **Parameters**:
  - `url`: The URL to check (e.g., `http://example.com`).
- **Response**:
  ```json
  {
    "matches": true,
    "source": ["google_safe_browsing", "phish_tank"]
  }
  ```
  - `matches`: `true` if the URL is flagged as malicious, otherwise `false`.
  - `source`: List of services that flagged the URL.

### Frontend
1. **Open `index.html` in your browser.**
2. **Enter the URL** you want to check in the input field.
3. **Click `Analyze Now`.**
4. **Results will be displayed below the input field:**
   - ✅ **Likely Safe**: No threats detected.
   - ⚠️ **Potential Phishing Risk**: The URL is flagged as malicious.

## Project Structure
```
safesurf/
├── app.py                  # Flask backend
├── index.html              # Frontend HTML file
├── README.md               # Project documentation
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables
├── static/                 # Static files (CSS, JS, images)
└── venv/                   # Virtual environment (ignored in Git)
```

## Testing
To test the system, use the following URLs:

### Safe URLs
- [Google](https://www.google.com)
- [GitHub](https://www.github.com)

### Malicious URLs
- [Google Safe Browsing Test URL](http://malware.testing.google.test/testing/malware/)
- [Historically Flagged Phishing URL](http://www.paypal-security-update.com)

---
SafeSurf ensures safer browsing by detecting malicious websites in real-time. 🚀🔒

