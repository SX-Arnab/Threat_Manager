import time

phishing_words = [
    "urgent", "action required", "immediately", "expired", "final notice",
    "suspended", "unauthorized", "compromised", "deactivated", "blocked",
    "security alert", "protocol violation", "terminate", "legal action",
    "invoice", "payment", "refund", "overdue", "wire transfer",
    "winning", "lottery", "inheritance", "claim", "bonus",
    "commission", "statement", "receipt", "transaction", "tax refund",
    "verify", "validate", "update profile", "reset password", "login",
    "sync", "security key", "mfa", "2fa", "enrollment",
    "re-authenticate", "linked account", "unusual activity",
    "it desk", "admin", "system administrator", "microsoft support",
    "billing department", "human resources", "payroll", "shipping label",
    "delivery failure", "docusign", "e-signature", "secure message",
    "account verification", "click here", "secure link", "password change",
    "important notice", "member update", "subscription", "billing error"
]

# --- Exercise 1 System ---
text = input("Type a Message:\n")

# Start with the assumption that the email is clean
Secure = True

# Scan EVERY word in the database
for word in phishing_words:
    if word in text.lower():  # .lower() catches "URGENT", "Login", etc.
        Secure = False
        break  # We found a threat! Now we stop checking and block it.

# Make the final verdict ONLY after the scan finishes looking
if Secure:
    print("Its sent\n\n")
else:
    print("It cant be sent\nIt seems suspicious\n\n")


# --- Exercise 2 System ---
text1 = "CLICK HERE NOW"

def scan():
    # Normalize the test string to lowercase
    filtered_text = text1.lower()
    
    # Define a clean, specific target to hunt for
    target_phrase = "click here"
    
    if target_phrase in filtered_text:
        print("Exercise 2 Result: SUS")
    else:
        print("Exercise 2 Result: done")

scan()
print("\n")


# --- Exercise 3 System ---
words_list = ['urgent', 'winner', 'login', 'crypto', 'gift card']
text2 = "urgent! you are the winner, login here for your crypto gift card"

# Counts how many distinct threat signatures triggered inside the payload string
count = sum(1 for word in words_list if word in text2.lower())

print(f"Exercise 3 Threat Density Metric: {count}")