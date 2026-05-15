import re
import os
import json


def load_engine_rules(json_path="rules.json"):
    """Loads and returns threat intelligence configuration rules from JSON."""
    if not os.path.exists(json_path):
        print(f"[!] Critical Error: Configuration file '{json_path}' missing!")
        # Fallback dictionary to keep the system alive if JSON is lost
        return {"threat_weights": {}, "heuristics_weights": {}, "malicious_tlds": []}
        
    with open(json_path, "r", encoding="utf-8") as file:
        return json.load(file)


def calculate_score(paras, rules_dict):
    """Calculates a total risk score based on words using weights from JSON."""
    total_score = 0
    # Access the weights directly from our loaded configuration layout
    weights = rules_dict.get("threat_weights", {})
    
    for item in paras:
        total_score += weights.get(item.lower(), 0.25)
    return total_score


def get_threat_level(score):
    """Maps float and integer engine scores to standard threat classification buckets."""
    if score <= 2:
        return "SAFE"
    elif 2 < score <= 5:
        return "SUSPICIOUS"
    else:
        return "DANGER"


def check_repeated_symbols(text):
    return "!!!!!" in text

def check_suspicious_capitalization(text):
    words = text.split()
    for word in words:
        if word.isalpha() and len(word) > 2 and word.isupper():
            return True
    return False

def check_url_encoding(text):
    pattern = r"%[0-9a-fA-F]{2}"
    return bool(re.search(pattern, text))

def check_double_extension(text):
    lowered = text.lower()
    return any(ext in lowered for ext in [".pdf.exe", ".docx.exe", ".txt.exe"])


def evaluate_advanced_threats(text, base_score, rules_dict):
    """Appends extra weight to the score if advanced rules are triggered."""
    bonus_score = 0
    heuristics = rules_dict.get("heuristics_weights", {})
    
    if check_repeated_symbols(text):
        bonus_score += heuristics.get("repeated_symbols", 3)
        
    if check_suspicious_capitalization(text):
        bonus_score += heuristics.get("suspicious_capitalization", 2)
        
    if check_url_encoding(text):
        bonus_score += heuristics.get("url_encoding", 4)
        
    if check_double_extension(text):
        bonus_score += heuristics.get("double_extension", 6)
        
    return base_score + bonus_score


# --- Day 4: Engine File Analysis & URL Scanner Pipelines ---
def url_checker(rules_dict):
    """Validates suspicious domain structure patterns using TLDs from JSON."""
    url = input("Enter the url:\n").lower().strip()
    
    # Dynamically build the regex pipeline using extensions defined inside the JSON
    tlds = rules_dict.get("malicious_tlds", [".xyz", ".top", ".ru"])
    tld_pattern = r"(" + "|".join([re.escape(tld) for tld in tlds]) + r")(/|$)"
    
    match = re.search(tld_pattern, url)
    count_hyphen = re.findall(r"-", url)
    ip_url = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)

    if len(count_hyphen) >= 2 or match or ip_url:
        print("[!] The URL feels suspicious. DO NOT CLICK\n")
    else:
        print('[+] It seems to be safe.\n')


def scan_log_file(file_path, rules_dict):
    """Reads a file line-by-line and correlates parameters from configuration rules."""
    danger_count = 0
    results = []

    if not os.path.exists(file_path):
        print(f"Error: Log file not found at {file_path}!")
        return 0, []

    print(f"\n--- SOC Engine: Scanning {file_path} ---")
    
    with open(file_path, "r", encoding="utf-8") as file:
        for index, line in enumerate(file, start=1):
            cleaned_line = line.strip()
            if not cleaned_line:
                continue
                
            words = cleaned_line.split()
            
            # Feed the dynamic rules into the calculations
            base_score = calculate_score(words, rules_dict)
            final_score = evaluate_advanced_threats(cleaned_line, base_score, rules_dict)
            level = get_threat_level(final_score)
            
            if level == "DANGER":
                danger_count += 1
                print(f"[ALERT] Line {index} => {level} (Score: {final_score})")
            
            results.append(f"Line {index}: {level} (Score: {final_score}) | {line}")

    return danger_count, results


def save_report(results, output_file="Reports/scan_report.txt"):
    dir_name = os.path.dirname(output_file)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name)
        
    with open(output_file, "w", encoding="utf-8") as f:
        f.writelines(results)
    print(f"[*] Report safely exported to: {output_file}")