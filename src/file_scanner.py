from func import scan_log_file, save_report

total_threats, full_report = scan_log_file(r"Data\logs.txt")

print(f"\nScan Complete. Total Dangerous Lines Found: {total_threats}")

# Save the reuslts
save_report(full_report)



# Inside your scoring/main logic file
from func import (
    check_repeated_symbols,
    check_suspicious_capitalization,
    check_url_encoding,
    check_double_extension
)

def evaluate_advanced_threats(text, base_score):
    """Appends extra weight to the score if advanced rules are triggered."""
    bonus_score = 0
    
    if check_repeated_symbols(text):
        print("[!] Rule Triggered: Excessive Exclamation Marks (+3)")
        bonus_score += 3
        
    if check_suspicious_capitalization(text):
        print("[!] Rule Triggered: Aggressive Capitalization (+2)")
        bonus_score += 2
        
    if check_url_encoding(text):
        print("[!] Rule Triggered: Obfuscated URL Encoding (+4)")
        bonus_score += 4
        
    if check_double_extension(text):
        print("[!] CRITICAL Rule Triggered: Double File Extension Detected (+6)")
        bonus_score += 6
        
    return base_score + bonus_score

evaluate_advanced_threats("FREE MONEY !!!!!", 1)