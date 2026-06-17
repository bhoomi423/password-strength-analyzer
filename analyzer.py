import re
import sqlite3
import secrets
import string

# --- Common password list check ---
def load_common_passwords(filepath="common_passwords.txt"):
    try:
        with open(filepath, "r") as f:
            return set(line.strip().lower() for line in f)
    except FileNotFoundError:
        return set()

# --- Strength Checker ---
def check_strength(password, common_passwords=set()):
    score = 0
    feedback = []

    # Length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Too short. Use at least 8 characters (12+ recommended).")

    # Uppercase
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("❌ Add uppercase letters (A-Z).")

    # Lowercase
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("❌ Add lowercase letters (a-z).")

    # Digits
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("❌ Add numbers (0-9).")

    # Special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 2
    else:
        feedback.append("❌ Add special characters (!@#$%^&*).")

    # Common password check
    if password.lower() in common_passwords:
        score = 0
        feedback.append("🚨 This is a commonly used password. Change it immediately.")

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        feedback.append("⚠️  Avoid repeating characters (e.g., 'aaa', '111').")

    # Rating
    if score >= 6:
        rating = "💪 Strong"
    elif score >= 4:
        rating = "⚠️  Moderate"
    else:
        rating = "❌ Weak"

    return score, rating, feedback

# --- Suggest a strong password ---
def suggest_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

# --- Optional: SQLite DB for reuse prevention ---
def init_db():
    conn = sqlite3.connect("used_passwords.db")
    conn.execute("CREATE TABLE IF NOT EXISTS passwords (hash TEXT UNIQUE)")
    conn.commit()
    return conn

def is_reused(password, conn):
    import hashlib
    hashed = hashlib.sha256(password.encode()).hexdigest()
    cur = conn.execute("SELECT 1 FROM passwords WHERE hash=?", (hashed,))
    return cur.fetchone() is not None

def save_password(password, conn):
    import hashlib
    hashed = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn.execute("INSERT INTO passwords (hash) VALUES (?)", (hashed,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Already exists

# --- Main ---
def main():
    common = load_common_passwords()
    conn = init_db()

    print("=== 🔐 Password Strength Analyzer ===\n")
    password = input("Enter a password to analyze: ")

    if is_reused(password, conn):
        print("\n🚨 This password has been used before. Please choose a new one.")
    else:
        score, rating, feedback = check_strength(password, common)
        print(f"\nStrength Score : {score}/7")
        print(f"Rating         : {rating}")

        if feedback:
            print("\nFeedback:")
            for f in feedback:
                print(f"  {f}")

        print(f"\n💡 Suggested strong password: {suggest_password()}")
        save_password(password, conn)
        print("\n✅ Password analyzed and stored (hashed) for future reuse detection.")

if __name__ == "__main__":
    main()