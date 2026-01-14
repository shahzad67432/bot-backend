from flask import Flask, redirect, session, request, jsonify
from google_auth_oauthlib.flow import Flow
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from flask_cors import CORS
from dotenv import load_dotenv
import os
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import base64
import aiml
import glob
from difflib import SequenceMatcher
from cryptography.fernet import Fernet
from neo4j import GraphDatabase

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

key = os.environ.get("FLASK_ENCRYPTION_KEY").encode()
print(key)
cipher_suite = Fernet(key)

# Setup the Neo4j database connection
neo4j_uri = "neo4j://127.0.0.1:7687"
neo4j_user = "neo4j"
neo4j_password = '11223344'
driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

app = Flask(__name__)
app.secret_key = "flask-secretkey123"
CORS(app, supports_credentials=True, origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"])
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
SECRET_KEY = "secretkey123"

bot = aiml.Kernel()
aiml_files = glob.glob("./folder/data/*.aiml")

bot.setBotPredicate("master", "NE-TEAM")
bot.setBotPredicate("name", "Neural Mail Assistant")

for file in aiml_files:
    bot.learn(file)

TEACHERS = [
    {"name": "Dr. Ashfaq Ahmad", "email": "ashfaqahmad@umt.edu.pk"},
    {"name": "Usama Amjad", "email": "usama.amjad@umt.edu.pk"},
    {"name": "Mahmood Hussain", "email": "mahmood.hussain@umt.edu.pk"},
    {"name": "Muhammad Shahzad Ali", "email": "shaa1891640@gmail.com"},
    {"name": "Prof. Omar Farooq", "email": "omar.farooq@university.edu"},
    {"name": "Dr. Ayesha Siddiqui", "email": "ayesha.siddiqui@university.edu"},
    {"name": "Dr. Imran Sheikh", "email": "imran.sheikh@university.edu"},
    {"name": "Prof. Zainab Ahmed", "email": "zainab.ahmed@university.edu"},
    {"name": "Dr. Bilal Akram", "email": "bilal.akram@university.edu"},
    {"name": "Dr. Hina Raza", "email": "hina.raza@university.edu"}
]

# ==================== KEYWORD CATEGORIES ====================
ILLNESS_KEYWORDS = ['ill', 'sick', 'unwell', 'fever', 'not feeling well', 'health issue', 'medical', 'disease', 'pain']
LEAVE_KEYWORDS = ['leave', 'absent', 'cannot come', "can't come", "won't come", "won't attend", 'miss class',
                  "can't attend", 'unable to attend', 'might not be able to come', 'I will not come', 'will not come',
                  'might not attend', 'might not be able to attend']
URGENT_KEYWORDS = ['urgent', 'important', 'emergency', 'immediately', 'asap', 'critical', 'pressing']

# ==================== EMAIL TEMPLATES ====================
EMAIL_TEMPLATES = {
    'sick_leave': {
        'subject': 'Sick Leave Request - {student_name}',
        'body': '''Dear {teacher_name},

I hope this email finds you well. I am writing to inform you that I am currently unwell and will not be able to attend your class today.

I kindly request you to grant me leave for today's session. I will ensure to catch up on any missed work and assignments at the earliest.

Thank you for your understanding.

Best regards,
{student_name}
{student_email}'''
    },
    'general_leave': {
        'subject': 'Leave Request - {student_name}',
        'body': '''Dear {teacher_name},

I hope this email finds you well. I am writing to request leave as I will be unable to attend your class today due to unavoidable circumstances.

I kindly request your approval for this absence. I will make sure to cover all missed content and complete any pending assignments.

Thank you for your consideration.

Best regards,
{student_name}
{student_email}'''
    },
    'urgent_work': {
        'subject': 'Urgent: {student_name} - Important Matter',
        'body': '''Dear {teacher_name},

I hope this email finds you well. I am reaching out regarding an urgent matter that requires your attention.

I would greatly appreciate if we could discuss this at your earliest convenience.

Thank you for your time and consideration.

Best regards,
{student_name}
{student_email}'''
    },
    'generic': {
        'subject': 'Message from {student_name}',
        'body': '''Dear {teacher_name},

I hope this email finds you well.

{message}

Thank you for your time.

Best regards,
{student_name}
{student_email}'''
    }
}


# flask working fine
@app.route("/")
def index():
    print("hello")
    return "<h2>Backend Working...</h2>"


# ----------------
# route to start the OauthConsent
@app.route('/oAuth-consent', methods=['POST', 'GET'])
def oauth_consent():
    token = request.args.get("token")

    if not token:
        return jsonify({"error": "Token required"}), 400

    try:
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
    """Store Gmail OAuth credentials in Neo4j."""
    neo4j_session = driver.session()

    try:
        neo4j_session.run("""
            MERGE (u:User {email: $email})
            SET u.token = $token,
                u.refresh_token = $refresh_token,
                u.expiry = $expiry,
                u.scopes = $scopes
        """, {
            "email": email,
            "token": data["token"],
            "refresh_token": data["refresh_token"],
            "expiry": data["expiry"],
            "scopes": ','.join(data["scopes"])
        })
    except Exception as e:
        print(f"Error storing credentials: {e}")
    finally:
        neo4j_session.close()


@app.route('/oauth2callback')
def oauth2callback():
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


def similarity_score(str1, str2):
    """Calculate similarity between two strings (0 to 1)"""
    return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()


def find_teacher(text):
    """Find teacher name from text using fuzzy matching"""
    text_lower = text.lower()
    best_match = None
    best_score = 0

    for teacher in TEACHERS:
        score = similarity_score(teacher['name'], text)
        if score > best_score:
            best_score = score
            best_match = teacher

        name_parts = teacher['name'].lower().split()
        for part in name_parts:
            if len(part) > 2 and part in text_lower:
                score = 0.8
                if score > best_score:
                    best_score = score
                    best_match = teacher

    if best_score > 0.6:
        return best_match
    return None


def detect_email_type(text):
    """Detect email type from text based on keywords"""
    text_lower = text.lower()

    has_illness = any(keyword in text_lower for keyword in ILLNESS_KEYWORDS)
    has_leave = any(keyword in text_lower for keyword in LEAVE_KEYWORDS)
    has_urgent = any(keyword in text_lower for keyword in URGENT_KEYWORDS)

    if has_illness and has_leave:
        return 'sick_leave'
    elif has_leave:
        return 'general_leave'
    elif has_urgent:
        return 'urgent_work'
    else:
        return 'generic'


def get_student_name(email):
    """Extract student name from email (simple extraction)"""
    name_part = email.split('@')[0]
    name = name_part.replace('.', ' ').replace('_', ' ').title()
    return name


def get_user_credentials_from_neo4j(user_email):
    """Retrieve OAuth credentials from Neo4j."""
    neo4j_session = driver.session()
    try:
        result = neo4j_session.run("""
            MATCH (u:User {email: $email})
            RETURN u.token AS token, u.refresh_token AS refresh_token, u.expiry AS expiry
        """, {"email": user_email})

        record = result.single()
        if not record:
            return None

        return {
            "token": record["token"],
            "refresh_token": record["refresh_token"],
            "expiry": record["expiry"]
        }
    finally:
        neo4j_session.close()


def get_user_credits(user_email):
    """Get user credits from Neo4j."""
    neo4j_session = driver.session()
    try:
        result = neo4j_session.run("""
            MATCH (u:User {email: $email})
            RETURN u.credits AS credits
        """, {"email": user_email})

        record = result.single()
        if not record or record["credits"] is None:
            # Initialize credits if not set
            neo4j_session.run("""
                MATCH (u:User {email: $email})
                SET u.credits = 10
            """, {"email": user_email})
            return 10

        return record["credits"]
    finally:
        neo4j_session.close()


def deduct_credit_and_save_history(user_email, receiver_email, teacher_name, email_type):
    """Deduct credit and save email history in Neo4j."""
    neo4j_session = driver.session()
    try:
        # Deduct credit
        result = neo4j_session.run("""
            MATCH (u:User {email: $email})
            WHERE u.credits > 0
            SET u.credits = u.credits - 1
            RETURN u.credits AS credits
        """, {"email": user_email})

        record = result.single()
        if not record:
            return None

        # Save email history
        neo4j_session.run("""
            MATCH (u:User {email: $email})
            CREATE (e:EmailHistory {
                receiverEmail: $receiver_email,
                receiverName: $receiver_name,
                emailType: $email_type,
                status: 'sent',
                timestamp: datetime()
            })
            CREATE (u)-[:SENT]->(e)
        """, {
            "email": user_email,
            "receiver_email": receiver_email,
            "receiver_name": teacher_name,
            "email_type": email_type
        })

        return record["credits"]
    finally:
        neo4j_session.close()


# ==================== UPDATED SEND EMAIL ROUTE ====================
@app.route('/send-email', methods=['POST', 'GET'])
def send_email():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    token = data.get("token")
    speech = data.get("speechText")

    if not token:
        return jsonify({"error": "Token required"}), 400

    if not speech:
        return jsonify({"error": "Speech text required"}), 400

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_email = decoded.get("email")
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # 1. Find teacher from speech text
    teacher = find_teacher(speech)
    if not teacher:
        return jsonify({
            "error": "Teacher not found",
            "message": "Could not identify the teacher. Please mention the teacher's name clearly.",
            "available_teachers": [t['name'] for t in TEACHERS]
        }), 400

    # 2. Detect email type
    email_type = detect_email_type(speech)

    # 3. Get student name from email
    student_name = get_student_name(user_email)

    # 4. Select appropriate template
    template = EMAIL_TEMPLATES[email_type]

    # 5. Format email content
    subject = template['subject'].format(
        student_name=student_name,
        teacher_name=teacher['name']
    )

    if email_type == 'generic':
        body = template['body'].format(
            teacher_name=teacher['name'],
            student_name=student_name,
            student_email=user_email,
            message=speech
        )
    else:
        body = template['body'].format(
            teacher_name=teacher['name'],
            student_name=student_name,
            student_email=user_email
        )

    receiver_email = teacher['email']

    # Get OAuth credentials from Neo4j
    credentials_data = get_user_credentials_from_neo4j(user_email)
    if not credentials_data:
        return jsonify({"error": "No OAuth credentials found for this user"}), 404

    access_token = credentials_data["token"]
    refresh_token = credentials_data["refresh_token"]

    # Handle encryption
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

    # Create HTML email
    html_body = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
              {body.replace(chr(10), '<br>')}
            </div>
            <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
            <p style="font-size: 12px; color: #888; text-align: center;">
              Sent via Neural Mail Assistant
            </p>
          </body>
        </html>
    """

    message = MIMEText(html_body, "html")
    message['to'] = receiver_email
    message['from'] = user_email
    message['subject'] = subject

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    # Send email
    try:
        print("sending email", receiver_email, email_type)
        sent = service.users().messages().send(
            userId='me',
            body={'raw': raw_message}
        ).execute()

        # Deduct credit and save history
        updated_credits = deduct_credit_and_save_history(
            user_email, receiver_email, teacher['name'], email_type
        )

        if updated_credits is None:
            return jsonify({"error": "Insufficient credits"}), 402

        return jsonify({
            "status": "success",
            "message_id": sent['id'],
            "details": {
                "teacher": teacher['name'],
                "email_type": email_type,
                "receiver": receiver_email
            }
        })
    except Exception as e:
        return jsonify({"error": "Failed to send email", "details": str(e)}), 500


def get_user_id_from_token(auth_token):
    try:
        decoded = jwt.decode(
            auth_token,
            SECRET_KEY,
            algorithms=["HS256"]
        )
        return decoded.get("userId")
    except ExpiredSignatureError:
        raise Exception("Token has expired")
    except InvalidTokenError:
        raise Exception("Invalid token")



@app.route('/bot-chat', methods=['GET'])
def bot_chat():
    human_input = request.args.get("human_input", "")
    email = request.args.get("email", "")
    name = request.args.get("name", "")
    auth_token = request.args.get("auth_token", "")

    if not auth_token:
        return jsonify({"error": "No authorization token provided"}), 400
    if not human_input:
        return jsonify({"error": "No data provided"}), 400

    user_id = get_user_id_from_token(auth_token)

    user_message = create_message(user_id, "user", human_input)

    bot.setPredicate("name", name)
    bot.setPredicate("lastname", name)
    bot.setPredicate("firstname", name)
    bot.setPredicate("email", email)

    bot_response = bot.respond(human_input)

    bot_message = create_message(user_id, "bot", bot_response)
    if not bot_message:
        print("Warning: Failed to save bot message to database")

    return jsonify({
        "content": bot_response,
        "userMessage": human_input,
        "botMessage": bot_message
    })


def create_message(user_id, role, content):
    """Create a new Message node and link it to User in Neo4j."""
    neo4j_session = driver.session()
    try:
        result = neo4j_session.run("""
            MATCH (u:User {id: $userId})
            CREATE (m:Message {
                id: randomUUID(),
                role: $role,
                content: $content,
                createdAt: datetime(),
                userId: $userId
            })
            CREATE (u)-[:SENT_MESSAGE]->(m)
            RETURN m.id AS id, 
                   m.userId AS userId, 
                   m.role AS role, 
                   m.content AS content, 
                   m.createdAt AS createdAt
        """, {
            "userId": user_id,
            "role": role,
            "content": content
        })

        record = result.single()
        if not record:
            return None

        return {
            "id": record["id"],
            "userId": record["userId"],
            "role": record["role"],
            "content": record["content"],
            "createdAt": record["createdAt"].iso_format() if record["createdAt"] else None
        }
    except Exception as e:
        print(f"Error creating message: {e}")
        return None
    finally:
        neo4j_session.close()

if __name__ == '__main__':
    app.run(debug=True)