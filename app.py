from flask import Flask, redirect, session, request, jsonify
from google_auth_oauthlib.flow import Flow
import jwt
from flask_cors import CORS
from dotenv import load_dotenv
import psycopg2
import os
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import base64
import aiml
import glob
from cryptography.fernet import Fernet
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

key = os.environ.get("FLASK_ENCRYPTION_KEY").encode()
print(key)
cipher_suite = Fernet(key)


app = Flask(__name__)
app.secret_key= "flask-secretkey123"
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
scopes = [
    'https://www.googleapis.com/auth/gmail.send',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]
load_dotenv()

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
BASE_URL = os.getenv("BASE_URL")
NEXT_API_URL = "http://localhost:3000"
SECRET_KEY="secretkey123"
DB_URL = os.getenv("DATABASE_URL")

bot = aiml.Kernel()
aiml_files = glob.glob("./folder/data/*.aiml")

bot.setBotPredicate("name", "Shahzad's bot")
bot.setBotPredicate("master", "Shahzad")

for file in aiml_files:
    bot.learn(file)



#flask working fine
@app.route("/")
def index():
    print("hello")
    return "<h2>Hello world</h2>"
# ----------------
# route to  start the OauthConsent
@app.route('/oAuth-consent', methods=['POST', 'GET']) #get the email, from frontend
def oauth_consent():
    token = request.args.get("token")

    if not token:
        return jsonify({"error": "Token required"}), 400

    try:
        # ✅ Verify the JWT token (same secret used in Next.js)
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = decoded.get("email")
        print("email:", email)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=scopes,
        redirect_uri=f"{BASE_URL}/oauth2callback"
    )

    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )

    session["email"] = email
    session["state"] = state
    return redirect(auth_url)


def store_gmail_credentials(email, data):
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()

    try:
        # Insert or update in one transaction
        cur.execute("""
            INSERT INTO "UserOAuth" (token, refresh_token, expiry, scopes, "userId")
            VALUES (
                %(token)s, %(refresh_token)s, %(expiry)s, %(scopes)s,
                (SELECT id FROM "User" WHERE email = %(email)s)
            )
            ON CONFLICT ("userId") DO UPDATE SET
                token = EXCLUDED.token,
                refresh_token = EXCLUDED.refresh_token,
                expiry = EXCLUDED.expiry,
                scopes = EXCLUDED.scopes;
        """, {
            "token": data["token"],
            "refresh_token": data["refresh_token"],
            "expiry": data["expiry"],
            "scopes": data["scopes"] if isinstance(data["scopes"], list) else [data["scopes"]],
            "email": email
        })

        conn.commit()
    finally:
        cur.close()
        conn.close()
@app.route('/oauth2callback')
def oauth2callback():
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()

    state = session.get("state")
    email = session.get("email")
    if not email:
        return "Email missing", 400

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=scopes,
        redirect_uri=f"{BASE_URL}/oauth2callback",
    )

    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "scopes": credentials.scopes,
        "email": email,
        "expiry": str(credentials.expiry),
    }
    data["token"] = cipher_suite.encrypt(data["token"].encode()).decode()
    data["refresh_token"] = cipher_suite.encrypt(data["refresh_token"].encode()).decode()
    try:
        store_gmail_credentials(email, data)
        return redirect(f"{NEXT_API_URL}?connected=gmail")
    except Exception as e:
        return jsonify({"error": "Failed to store Gmail data", "details": str(e)}), 500


@app.route('/send-email', methods=['POST', 'GET'])
def send_email():
    data = request.get_json()  # <- get JSON body
    if not data:
        return jsonify({"error": "No data provided"}), 400

    token = data.get("token")
    speech = data.get("speechText")
    receiver_email = 'f2023376234@umt.edu.pk'

    if not token:
        return jsonify({"error": "Token required"}), 400

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_email = decoded.get("email")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    try:
        cur.execute("""
                    SELECT token, refresh_token, expiry
                    FROM "UserOAuth"
                    WHERE "userId" = (SELECT id FROM "User" WHERE email = %s)
                    """, (user_email,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "No OAuth credentials found for this user"}), 404

        access_token, refresh_token, expiry = row
    finally:
        cur.close()
        conn.close()

    if user_email == "shaa1891640@gmail.com":
        access_token = cipher_suite.encrypt(access_token.encode()).decode()
        refresh_token = cipher_suite.encrypt(refresh_token.encode()).decode()

    decrypted_access_token = cipher_suite.decrypt(access_token.encode()).decode()
    decrypted_refresh_token = cipher_suite.decrypt(refresh_token.encode()).decode()

    # Build credentials object
    creds = Credentials(
        token=decrypted_access_token,
        refresh_token=decrypted_refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET
    )

    service = build('gmail', 'v1', credentials=creds)

    html_body = f"""
        <html>
          <body>
            <h2>Message from Your App</h2>
            <p>{speech}</p>
            <hr>
            <p>Sent via Your Email Assistant using Gmail API and AIML Bot</p>
          </body>
        </html>
    """
    message = MIMEText(html_body, "html")
    message['to'] = receiver_email
    message['from'] = user_email
    message['subject'] = "Message from your Muhammad Shahzad's Email Assistant"

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        sent = service.users().messages().send(
            userId='me',
            body={'raw': raw_message}
        ).execute()
        return jsonify({"status": "success", "message_id": sent['id']})
    except Exception as e:
        return jsonify({"error": "Failed to send email", "details": str(e)}), 500


@app.route('/bot-chat', methods=['GET'])
def bot_chat():
    human_input = request.args.get("human_input", "")
    if not human_input:
        return jsonify({"error": "No data provided"}), 400
    response = bot.respond(human_input)
    return response