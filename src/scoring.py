# Importing func from another file 
from func import get_threat_level, calculate_score
import time
from random import randint

duration = randint(1, 6)


# Getting text through user about wht he got
text = input("Email U got(Seperate with space):\n")
filtered_text = text.split()

# Using func defined in another file i.e 'func.py'
score = calculate_score(*filtered_text)
threat_level = get_threat_level(score)

print('Analyzing....')
start = time.time()
time.sleep(duration)
print(f"Your Score: {score}")
print(f"Your threat level: {threat_level}")
print(f"Scanned Completed in {time.time() - start:.4f} sec")
