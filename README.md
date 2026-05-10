# Phishing Autopsy

Phishing Autopsy is a local email-analysis sandbox for inspecting suspicious messages. It combines a Flask backend, a trained text-classification model, DNS sender-domain checks, and a React/Vite frontend for uploading raw `.eml` files or analyzing pasted email content.

The project is designed for experimentation and learning around phishing detection, not as a production email-security gateway.

## Features

- Analyze raw `.eml` email files.
- Extract sender domains from email headers.
- Parse plain-text and HTML email bodies.
- Score email text with a custom TF-IDF + Naive Bayes phishing model.
- Check sender-domain MX, SPF, and DMARC DNS records.
- Extract URLs and flag suspicious links based on simple URL heuristics.
- Produce analyst-oriented evidence including header mismatches, URL intelligence, language lure categories, attachments, risk factors, and score breakdown.
- Apply an extra heuristic boost for high-risk spear-phishing language such as urgent payment, invoice, transfer, and overdue terms.
- Display threat score, phishing verdict, authentication posture, link findings, and prioritized risk factors in a React analyst console.

## Tech Stack

- **Backend:** Python, Flask, Flask-CORS
- **Machine learning:** scikit-learn, pandas, joblib
- **DNS checks:** dnspython
- **Frontend:** React, Vite, Axios
- **Model artifacts:** `phishing_model.pkl`, `vectorizer.pkl`

## Project Structure

```text
phishing-autopsy/
+-- backend/
|   +-- app.py                    # Flask API for email analysis
|   +-- train_model.py            # Trains and saves the phishing classifier
|   +-- datasets/                 # Training CSV datasets
|   +-- phishing_model.pkl        # Saved scikit-learn model
|   +-- vectorizer.pkl            # Saved TF-IDF vectorizer
|   +-- test_emails/              # Sample .eml files for manual testing
|   +-- test_cases/               # Real-world style fixtures and expectations
|   +-- run_test_cases.py         # Runs fixture checks through the Flask test client
+-- docs/
|   +-- Phishing_Autopsy_Minor_Project_Report.docx
+-- scripts/
|   +-- generate_project_report_docx.js
+-- frontend/
    +-- package.json              # Frontend scripts and dependencies
    +-- vite.config.js            # Vite configuration
    +-- index.html
    +-- src/
        +-- App.jsx               # Main UI and API call
        +-- main.jsx
        +-- App.css
        +-- index.css
```

## Prerequisites

- Python 3.10 or newer
- Node.js 20 or newer
- npm

The frontend dependencies are already installed in this workspace, but a fresh clone should still run `npm install`.

## Backend Setup

Open a terminal in the backend directory:

```powershell
cd backend
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the Python dependencies:

```powershell
pip install flask flask-cors dnspython joblib pandas scikit-learn
```

Start the Flask API:

```powershell
python app.py
```

The backend runs at:

```text
http://127.0.0.1:5000
```

## Frontend Setup

Open a second terminal in the frontend directory:

```powershell
cd frontend
```

Install dependencies if needed:

```powershell
npm install
```

Start the Vite dev server:

```powershell
npm run dev
```

Vite will print the local app URL, usually:

```text
http://localhost:5173
```

Keep both the backend and frontend running while using the app.

## How to Use

1. Start the Flask backend from `backend/`.
2. Start the React frontend from `frontend/`.
3. Open the Vite URL in your browser.
4. Upload a raw `.eml` file, or provide email text and a sender domain.
5. Review the returned threat score, verdict, explanation, and DNS checks.

Sample emails are available in:

```text
backend/test_emails/
```

The sample set includes safe mail, bank credential phishing, CEO fraud, Reply-To mismatch, URL-shortener lure, HTML brand impersonation, IP-address login lure, and a benign internal build report.

Real-world style regression fixtures are available in:

```text
backend/test_cases/
```

## API

### Analyze an uploaded `.eml` file

```http
POST /api/analyze
Content-Type: multipart/form-data
```

Form field:

```text
file=<email.eml>
```

Example with curl:

```powershell
curl.exe -X POST http://127.0.0.1:5000/api/analyze -F "file=@backend/test_emails/2_Scam_Bank_Alert.eml"
```

### Analyze text directly

The backend accepts either form fields or JSON for direct text analysis. The React frontend uses form fields.

Form fields:

```text
email_text=Urgent payment transfer required today...
sender_domain=example.com
```

JSON request:

```http
POST /api/analyze
Content-Type: application/json
```

Request body:

```json
{
  "email_text": "Urgent payment transfer required today...",
  "sender_domain": "example.com"
}
```

Example response:

```json
{
  "dns_analysis": {
    "mx_found": true,
    "spf_found": true,
    "dmarc_found": false
  },
  "extracted_domain": "example.com",
  "score_breakdown": {
    "model_probability": 88,
    "heuristic_points": 24,
    "final_score": 85,
    "verdict": "high_risk"
  },
  "risk_factors": [
    {
      "severity": "high",
      "category": "Links",
      "signal": "Suspicious URL pattern",
      "detail": "1 link(s) matched suspicious URL heuristics.",
      "points": 8
    }
  ],
  "link_analysis": {
    "total_links": 1,
    "suspicious_count": 1,
    "unique_domains": [
      "secure-login-example.com"
    ]
  },
  "ai_analysis": {
    "threat_score": 85,
    "is_phishing": true,
    "links": [
      "http://secure-login-example.com/login"
    ],
    "suspicious_links": [
      {
        "url": "http://secure-login-example.com/login",
        "reasons": [
          "plain HTTP",
          "domain differs from sender"
        ]
      }
    ],
    "explanation": "Model phishing probability is 88%. Evidence review found 3 risk factor(s), including 1 suspicious link(s)."
  }
}
```

## Training the Model

The classifier is trained from CSV files in `backend/datasets/`. The training script currently looks for:

```text
emails.csv
phishing_email.csv
CEAS_08.csv
Enron.csv
Ling.csv
Nazario.csv
Nigerian_Fraud.csv
SpamAssasin.csv
```

The script accepts these common dataset shapes:

- `label,text`
- `text_combined,label`
- `subject,body,label`
- `subject,body,urls,label`

Labels are normalized into:

```text
0 = legitimate / ham / safe
1 = phishing / spam / scam / malicious
```

The current training script:

- loads and normalizes all available datasets from `backend/datasets/`
- combines subject, body, and URL fields when needed
- removes duplicate email text
- uses `TfidfVectorizer` with word unigrams and bigrams
- trains a `ComplementNB` classifier
- uses a stratified 80/20 train/test split

To retrain the model:

```powershell
cd backend
python train_model.py
```

`train_modify.py` is also available as a compatibility wrapper and runs the same training pipeline:

```powershell
python train_modify.py
```

This regenerates:

```text
backend/phishing_model.pkl
backend/vectorizer.pkl
```

## Frontend Scripts

From the `frontend/` directory:

```powershell
npm run dev      # Start local development server
npm run build    # Build production assets
npm run preview  # Preview the production build
npm run lint     # Run ESLint
```

## Test Cases

The project includes synthetic real-world style `.eml` fixtures for:

- benign operational mail
- credential harvesting
- CEO/vendor payment fraud
- Reply-To mismatch
- URL shortener lure
- invoice attachment lure
- HTML brand impersonation
- IP-address login lure
- multi-domain tracking lure
- benign internal engineering report
- benign newsletter content

Run them from `backend/`:

```powershell
python run_test_cases.py
```

The runner posts each fixture to `/api/analyze` through Flask's test client and validates score ranges, expected verdicts, and expected evidence categories.

## Project Report

A compiled Word report is available at:

```text
docs/Phishing_Autopsy_Minor_Project_Report.docx
```

To regenerate it:

```powershell
node scripts/generate_project_report_docx.js
```

## Current Limitations

- Link analysis is heuristic-based. It flags plain HTTP links, URL shorteners, IP-address hosts, punycode domains, and links whose host differs from the claimed sender domain. It does not follow redirects, fetch pages, inspect reputation feeds, or detect every brand impersonation.
- DNS analysis checks MX, SPF, and DMARC record presence only. It does not validate DKIM signatures, SPF alignment, DMARC policy strength, or full email authentication results from received headers.
- The model is only as reliable as the dataset in `emails.csv`.
- The threat score combines model probability with a small rules-based heuristic, so it should be treated as a decision-support signal rather than a final verdict.
- The app is configured for local development and does not include production authentication, rate limiting, logging, or deployment configuration.

## Resolved Limitations

- Manual text analysis from the frontend now works with the backend because the API accepts form fields as well as JSON.
- URL extraction is implemented and suspicious links are returned with human-readable reasons.
- DNS checks now run independently for MX, SPF, and DMARC, so one missing or failing lookup does not prevent the others from being evaluated.
- Backend model and dataset paths are resolved relative to `backend/`, reducing path errors when scripts are launched from another working directory.
- The frontend now presents a technical analyst console with model scoring, heuristic scoring, authentication checks, URL intelligence, language signals, and prioritized findings.

## Troubleshooting

### `FileNotFoundError` for `phishing_model.pkl`, `vectorizer.pkl`, or `emails.csv`

Confirm the files exist in `backend/`. To regenerate the model artifacts from the dataset:

```powershell
cd backend
python train_model.py
```

### Frontend says analysis failed

Make sure the Flask backend is running at:

```text
http://127.0.0.1:5000
```

### DNS results are missing or false

The sender domain may be empty, invalid, unreachable, or missing MX, SPF, or DMARC records. DNS failures are caught by the backend and returned as failed checks.

## Disclaimer

Phishing Autopsy is a research and learning tool. Do not rely on it as the only control for blocking, approving, or responding to suspicious emails.
