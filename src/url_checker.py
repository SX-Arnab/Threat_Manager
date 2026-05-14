import re

url = input("Enter the url:\n").lower().strip()
match = re.search(r"(\.xyz|\.top|\.ru)$", url)
count_hyphen = re.findall(r"-", url)
pattern = r"[1-9]"
ip_url = re.match(pattern, url)


if len(count_hyphen) >=2 or match or ip_url:
    print("The URl feels suspicious. DO NOT CLICK\n\n")

else:
    print('It seems to be safe.')
