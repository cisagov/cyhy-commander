#!/usr/bin/env python3

# Standard Python Libraries
import random
import sys
import time

MEAN_SLEEP_TIME = 60

t = random.expovariate(1.0 / MEAN_SLEEP_TIME)
print("Sleeping for {:0.1f} seconds.".format(t))
time.sleep(t)
print("Done")
sys.exit(0)
