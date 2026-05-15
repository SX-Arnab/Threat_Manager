import re

THREAT_WEIGHTS = {
    "urgent": 2,
    "verify": 3,
    "login": 4,
    "password": 4,
    "free money": 5,
    ".ru": 5,
    "bit.ly": 3,
    '.top':5,
    'gift_code': 2
}

#  Calculates a total risk score based on a list of discovered keywords/features.
def calculate_score(*paras):
    total_score = 0
    for item in paras:
        total_score += THREAT_WEIGHTS.get(item.lower(), 0.25)
    
    return total_score


# To get threat level
def get_threat_level(score):
    if score <= 2:
        return "SAFE"
    elif 3 <= score <= 5:
        return "SUSPICIOUS"
    else:
        return "DANGER"
    
def url_checker():
    url = input("Enter the url:\n").lower().strip()
    match = re.search(r"(\.xyz|\.top|\.ru)$", url)
    count_hyphen = re.findall(r"-", url)
    pattern = r"[1-9]"
    ip_url = re.match(pattern, url)


    if len(count_hyphen) >=2 or match or ip_url:
        print("The URl feels suspicious. DO NOT CLICK\n\n")

    else:
        print('It seems to be safe.')

def scan_log_file(file_path):
    danger_count = 0
    results = []

    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
            
            print(f"--- Scanning {file_path} ({len(lines)} lines) ---")
            
            for index, line in enumerate(lines, start=1):
                # Clean the line and split into words
                words = line.strip().split()
                
                # Use your Day 3 Engine!
                score = calculate_score(*words)
                level = get_threat_level(score)
                
                if level == "DANGER":
                    danger_count += 1
                    print(f"Line {index} => {level} (Score: {score})")
                
                results.append(f"Line {index}: {level} | {line}")

        return danger_count, results

    except FileNotFoundError:
        print("Error: Log file not found!")
        return 0, []

def save_report(results, output_file= r"Reports\scan_report.txt"):
    with open(output_file, "w") as f:
        f.writelines(results)
    print(f"Report saved to {output_file}")