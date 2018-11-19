#!/bin/sh
nmap -iL *.txt --stats-every 60 -oX - -R -Pn -T4 --host-timeout 240m --max-scan-delay 5ms --max-retries 2 --min-parallelism 32 --defeat-rst-ratelimit -sV -O -sS -p1-65535
exitCode=$?
exit $exitCode
