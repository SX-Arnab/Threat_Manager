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
    "important notice", "member update", "subscription", "billing error", 'urgent', 'verify', 'password'
]

text = input("Type a Message:\n")

for words in phishing_words:

    if words in text:
        Secure = False
    elif words not in text:
        Secure = True

    if Secure == True:
        print("Its sent\n\n")
        break
    elif Secure == False:
        print("It cant be sent\nIt seems suspicious")
        break

# Mini Exercises

#1 done above

# 2
'''
text1 = "CLICK HERE NOW"

def scan():
    filetered_text = text1.lower()
    if words in filetered_text:
        print("SUS")
    else:
        print("done")

scan()
'''

#  3

'''
words = ['urgent', 'winner', 'login', 'crypto', 'gift card']
text2 = "urgent! you are the winner, login here for your crypto gift card"

count = sum(text2.count(word) for word in words)

print(f"Words level: {count}")
'''