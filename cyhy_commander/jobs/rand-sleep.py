#!/usr/bin/env python

import random
import time
import sys

MEAN_SLEEP_TIME = 60

t = random.expovariate(1.0 / MEAN_SLEEP_TIME)
print "Sleeping for %0.1f seconds." % t
time.sleep(t)
print "Done"
sys.exit(0)
