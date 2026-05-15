from func import scan_log_file, save_report

total_threats, full_report = scan_log_file(r"Data\logs.txt")

print(f"\nScan Complete. Total Dangerous Lines Found: {total_threats}")

# Save the reuslts
save_report(full_report)