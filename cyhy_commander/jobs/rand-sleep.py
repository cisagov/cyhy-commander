#!/usr/bin/env python3
"""Sleep for a random exponentially-distributed duration."""

# Standard Python Libraries
import random
import sys
import time

MEAN_SLEEP_TIME = 60

t = random.expovariate(1.0 / MEAN_SLEEP_TIME)
print(f"Sleeping for {t:0.1f} seconds.")
time.sleep(t)
print("Done")
sys.exit(0)
