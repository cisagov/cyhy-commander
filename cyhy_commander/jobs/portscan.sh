#!/bin/sh
nmap -iL *.txt -d2 --stats-every 60 -oN debug.out -oX - -R -Pn -T4 --host-timeout 120m --max-scan-delay 5ms --max-retries 2 --min-parallelism 32 --defeat-rst-ratelimit -sV -O -sS -p1-65535
exitCode=$?
gzip debug.out
exit $exitCode
