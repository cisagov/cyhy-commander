#!/bin/sh
nmap -iL *.txt -d2 --stats-every 60 -oN debug.out -oX - -n -sn -T4 --host-timeout 15m -PE -PP -PS443,80,1720,22,49152,21,53,61001,3479,25,62078,3389,8080,8008,8081,9100,8010,4000,1248,248,175,8087,9010,9004,8111,4502,10800,7776,2770,9886
exitCode=$?
gzip debug.out
exit $exitCode
