
import os
import re
import sqlite3
import time
from datetime import timedelta

from flask import (
    Flask, request, redirect, session,
    render_template_string, url_for
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)

# ---------------- APP CONFIGURATION ----------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY", "local-development-key-change-before-deployment"
)
app.permanent_session_lifetime = timedelta(minutes=20)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "users.db")

MAX_ATTEMPTS = 5
LOCK_TIME = 60

# Demo-only: attempts reset when the server restarts.
login_attempts = {}

SECURITY_QUESTIONS = [
    "What is your favourite colour?",
    "What is the name of your first school?",
    "What is your favourite food?"
]

# ---------------- DATABASE ----------------

def create_db():
    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    """)

    columns = [
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "security_question" not in columns:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN security_question TEXT
        """)

    if "security_answer_hash" not in columns:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN security_answer_hash TEXT
        """)

    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- PASSWORD VALIDATION ----------------

def password_is_valid(password):
    return bool(
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )


def password_strength(password):
    if len(password) < 8:
        return "Weak"

    if password_is_valid(password):
        return "Strong"

    return "Medium"


def hash_answer(answer):
    normalized = answer.strip().lower()
    return generate_password_hash(normalized)


def verify_answer(answer, stored_hash):
    normalized = answer.strip().lower()
    return check_password_hash(stored_hash, normalized)


# ---------------- COMMON PAGE DESIGN ----------------

STYLE = """
<style>
* { box-sizing: border-box; }

body {
    font-family: Arial, sans-serif;
    background: #eef2f7;
    margin: 0;
    padding: 25px 12px;
    color: #222;
}

.card {
    max-width: 440px;
    margin: 30px auto;
    background: white;
    padding: 25px;
    border-radius: 12px;
    box-shadow: 0 4px 18px #00000015;
}

h2 {
    text-align: center;
    color: #17365d;
}

input, select, button {
    width: 100%;
    padding: 12px;
    margin: 8px 0;
    border-radius: 6px;
    font-size: 15px;
}

input, select {
    border: 1px solid #bbb;
}

button {
    background: #1769aa;
    color: white;
    border: none;
    cursor: pointer;
}

button:hover {
    background: #124f80;
}

a { color: #1769aa; }

.message {
    color: #b42318;
    overflow-wrap: anywhere;
}

.links {
    text-align: center;
    line-height: 2;
}

.small {
    color: #555;
    font-size: 14px;
}
</style>
"""

STRENGTH_SCRIPT = """
<script>
function showStrength() {
    const p = document.getElementById("password");
    const s = document.getElementById("strength");

    if (!p || !s) return;

    const v = p.value;

    if (v.length < 8) {
        s.textContent = "Strength: Weak";
    } else if (
        /[A-Z]/.test(v) &&
        /[a-z]/.test(v) &&
        /[0-9]/.test(v) &&
        /[^A-Za-z0-9]/.test(v)
    ) {
        s.textContent = "Strength: Strong";
    } else {
        s.textContent = "Strength: Medium";
    }
}
</script>
"""


def render_page(title, body, **context):
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1.0">
        <title>{{ title }}</title>
        __STYLE__
    </head>
    <body>
        __BODY__
        __SCRIPT__
    </body>
    </html>
    """

    template = template.replace("__STYLE__", STYLE)
    template = template.replace("__BODY__", body)
    template = template.replace(
        "__SCRIPT__", context.pop("script", "")
    )

    return render_template_string(
        template, title=title, **context
    )


# ---------------- HOME ----------------

@app.route("/")
def home():
    body = """
    <div class="card">
        <h2>Secure Password Storage System</h2>
        <p>Register and log in to access your account.</p>

        <div class="links">
            <a href="{{ url_for('register') }}">Create Account</a>
            <br>
            <a href="{{ url_for('login') }}">Login</a>
            <br>
            <a href="{{ url_for('forgot_password') }}">
                Forgot Password?
            </a>
        </div>
    </div>
    """
    return render_page("Home", body)


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        question = request.form.get("security_question", "")
        answer = request.form.get("security_answer", "")

        if not username or not password or not answer.strip():
            message = "Please fill in all required fields."

        elif len(username) > 80:
            message = "Username must be 80 characters or fewer."

        elif question not in SECURITY_QUESTIONS:
            message = "Please select a valid security question."

        elif password != confirm:
            message = "Passwords do not match."

        elif not password_is_valid(password):
            message = (
                "Password must contain at least 8 characters, "
                "uppercase, lowercase, a number and a special character."
            )

        else:
            conn = get_db()

            try:
                conn.execute("""
                    INSERT INTO users
                    (username, password_hash,
                     security_question, security_answer_hash)
                    VALUES (?, ?, ?, ?)
                """, (
                    username,
                    generate_password_hash(password),
                    question,
                    hash_answer(answer)
                ))

                conn.commit()
                return redirect(url_for("login"))

            except sqlite3.IntegrityError:
                message = "Username already exists. Choose another."

            finally:
                conn.close()

    body = """
    <div class="card">
        <h2>Register</h2>
        <p class="message">{{ message }}</p>

        <form method="POST">
            <input name="username"
                   placeholder="Username"
                   maxlength="80" required>

            <input id="password" type="password"
                   name="password"
                   placeholder="Create password"
                   required oninput="showStrength()">

            <p id="strength" class="small">Strength: Weak</p>

            <p class="small">
                Minimum 8 characters, uppercase, lowercase,
                number and special character.
            </p>

            <input type="password" name="confirm"
                   placeholder="Confirm password" required>

            <label>Security question</label>

            <select name="security_question" required>
                {% for q in questions %}
                <option value="{{ q }}">{{ q }}</option>
                {% endfor %}
            </select>

            <input name="security_answer"
                   placeholder="Your security answer"
                   required>

            <button type="submit">Register</button>
        </form>

        <div class="links">
            <a href="{{ url_for('login') }}">Back to Login</a>
        </div>
    </div>
    """

    return render_page(
        "Register", body,
        message=message,
        questions=SECURITY_QUESTIONS,
        script=STRENGTH_SCRIPT
    )


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        now = time.time()

        attempts = login_attempts.get(username, {
            "count": 0,
            "locked_until": 0
        })

        if now < attempts["locked_until"]:
            remaining = int(attempts["locked_until"] - now) + 1
            message = (
                f"Temporarily locked. Try again in "
                f"{remaining} seconds."
            )

        else:
            conn = get_db()
            user = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            conn.close()

            if user and check_password_hash(
                user["password_hash"], password
            ):
                login_attempts.pop(username, None)
                session.clear()
                session.permanent = True
                session["username"] = username

                return redirect(url_for("dashboard"))

            attempts["count"] += 1

            if attempts["count"] >= MAX_ATTEMPTS:
                attempts["count"] = 0
                attempts["locked_until"] = now + LOCK_TIME

                message = (
                    "Too many failed attempts. "
                    "Try again after 60 seconds."
                )
            else:
                message = (
                    "Invalid username or password. "
                    f"Attempts left: "
                    f"{MAX_ATTEMPTS - attempts['count']}"
                )

            login_attempts[username] = attempts

    body = """
    <div class="card">
        <h2>Login</h2>
        <p class="message">{{ message }}</p>

        <form method="POST">
            <input name="username"
                   placeholder="Username" required>

            <input type="password" name="password"
                   placeholder="Password" required>

            <button type="submit">Login</button>
        </form>

        <div class="links">
            <a href="{{ url_for('forgot_password') }}">
                Forgot Password?
            </a>
            <br>
            <a href="{{ url_for('register') }}">Create Account</a>
        </div>
    </div>
    """

    return render_page("Login", body, message=message)


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) AS total FROM users"
    ).fetchone()["total"]
    conn.close()

    body = """
    <div class="card">
        <h2>Security Dashboard</h2>

        <p>Welcome, <strong>{{ username }}</strong>!</p>
        <p>Registered accounts: {{ count }}</p>
        <p>Password hashing: Enabled</p>
        <p>Login attempt protection: Enabled</p>

        <div class="links">
            <a href="{{ url_for('change_password') }}">
                Change Password
            </a>

            <form method="POST" action="{{ url_for('logout') }}">
                <button type="submit">Logout</button>
            </form>
        </div>
    </div>
    """

    return render_page(
        "Dashboard", body,
        username=session["username"], count=count
    )


# ---------------- CHANGE PASSWORD ----------------

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    message = ""

    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (session["username"],)
        ).fetchone()

        if not user or not check_password_hash(
            user["password_hash"], current
        ):
            message = "Current password is incorrect."

        elif new != confirm:
            message = "New passwords do not match."

        elif not password_is_valid(new):
            message = "New password does not meet the password rules."

        elif check_password_hash(user["password_hash"], new):
            message = "Choose a different password."

        else:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (
                    generate_password_hash(new),
                    session["username"]
                )
            )
            conn.commit()
            conn.close()

            session.clear()
            return redirect(url_for("login"))

        conn.close()

    body = """
    <div class="card">
        <h2>Change Password</h2>
        <p class="message">{{ message }}</p>

        <form method="POST">
            <input type="password" name="current_password"
                   placeholder="Current password" required>

            <input id="password" type="password"
                   name="new_password"
                   placeholder="New password"
                   required oninput="showStrength()">

            <p id="strength" class="small">Strength: Weak</p>

            <input type="password" name="confirm_password"
                   placeholder="Confirm new password" required>

            <button type="submit">Update Password</button>
        </form>

        <div class="links">
            <a href="{{ url_for('dashboard') }}">
                Back to Dashboard
            </a>
        </div>
    </div>
    """

    return render_page(
        "Change Password", body,
        message=message, script=STRENGTH_SCRIPT
    )


# ---------------- FORGOT PASSWORD ----------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()

        conn = get_db()
        user = conn.execute(
            """SELECT security_question, security_answer_hash
               FROM users WHERE username = ?""",
            (username,)
        ).fetchone()
        conn.close()

        if user and user["security_question"] and user["security_answer_hash"]:
            return redirect(url_for(
                "reset_password", username=username
            ))

        message = (
            "Account not found or no security question is registered. "
            "For older demo accounts, register a new account."
        )

    body = """
    <div class="card">
        <h2>Forgot Password</h2>

        <p>Enter your registered username to continue.</p>
        <p class="message">{{ message }}</p>

        <form method="POST">
            <input name="username"
                   placeholder="Registered username" required>

            <button type="submit">Continue</button>
        </form>

        <div class="links">
            <a href="{{ url_for('login') }}">Back to Login</a>
        </div>
    </div>
    """

    return render_page("Forgot Password", body, message=message)


# ---------------- RESET PASSWORD ----------------

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    username = request.args.get("username", "").strip()
    message = ""

    conn = get_db()
    user = conn.execute("""
        SELECT security_question, security_answer_hash, password_hash
        FROM users WHERE username = ?
    """, (username,)).fetchone()
    conn.close()

    if (
        not user
        or not user["security_question"]
        or not user["security_answer_hash"]
    ):
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        answer = request.form.get("security_answer", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not verify_answer(
            answer, user["security_answer_hash"]
        ):
            message = "Incorrect security answer."

        elif new != confirm:
            message = "Passwords do not match."

        elif not password_is_valid(new):
            message = (
                "Password must contain at least 8 characters, "
                "uppercase, lowercase, a number and a special character."
            )

        elif check_password_hash(user["password_hash"], new):
            message = "Choose a new password different from your old one."

        else:
            conn = get_db()
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (
                    generate_password_hash(new),
                    username
                )
            )
            conn.commit()
            conn.close()

            login_attempts.pop(username, None)
            return redirect(url_for("login"))

    body = """
    <div class="card">
        <h2>Reset Password</h2>

        <p><strong>Security question:</strong>
            {{ question }}
        </p>

        <p class="message">{{ message }}</p>

        <form method="POST">
            <input name="security_answer"
                   placeholder="Your security answer" required>

            <input id="password" type="password"
                   name="new_password"
                   placeholder="New password"
                   required oninput="showStrength()">

            <p id="strength" class="small">Strength: Weak</p>

            <input type="password" name="confirm_password"
                   placeholder="Confirm new password" required>

            <button type="submit">Reset Password</button>
        </form>
    </div>
    """

    return render_page(
        "Reset Password", body,
        question=user["security_question"],
        message=message,
        script=STRENGTH_SCRIPT
    )


# ---------------- LOGOUT ----------------

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# Create or update the database when the app starts.
create_db()


if __name__ == "__main__":
    app.run(debug=False)
