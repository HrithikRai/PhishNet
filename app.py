from flask import Flask, render_template
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
import html 
import cohere

co = cohere.ClientV2("enter_api_key_here_cohere")

app = Flask(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def detect_phishing(email_text):

    prompt = f"""
    You are a cybersecurity expert detecting phishing emails. Your job is to detect clickbait mails, phising links and potential scams.
    """
    
    response = co.chat(
        messages=[{"role": "system", "content": prompt},
                  {"role": "user", "content": f"Analyze this email for phishing attempts and write im short if its a phishing mail or not:\n\n{email_text}"}],
        model="command-r-plus-08-2024"
    )

    return response.message.content[0].text

def authenticate_gmail():
    """Authenticate and return Gmail service instance"""
    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
    creds = flow.run_local_server(port=8080, redirect_uri_trailing_slash=True)    
    return build("gmail", "v1", credentials=creds)

def get_emails():
    """Fetch emails from Gmail"""
    service = authenticate_gmail()
    results = service.users().messages().list(userId="me", maxResults=5).execute()
    messages = results.get("messages", [])

    email_list = []
    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
        msg_snippet = msg_data.get("snippet", "")
        msg_snippet = html.unescape(msg_snippet)  # Decode escaped characters like \u200c
        
        msg_payload = msg_data.get("payload", {})
        headers = msg_payload.get("headers", [])
        
        subject = "No Subject"
        sender = "Unknown"
        for header in headers:
            if header["name"] == "Subject":
                subject = header["value"]
            elif header["name"] == "From":
                sender = header["value"]

        email_list.append({"subject": subject, "from": sender, "snippet": msg_snippet})

    return email_list

@app.route("/")
def index():
    emails = get_emails()
    email_analysis = [(email, detect_phishing(email)) for email in emails]
    return render_template("index.html", email_analysis=email_analysis)

if __name__ == "__main__":
    app.run(debug=True)
