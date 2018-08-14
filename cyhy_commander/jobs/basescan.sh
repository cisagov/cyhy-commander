#!/bin/sh
nmap -iL *.txt -d2 --stats-every 60 -oN debug.out -oX - -n -T5 -sV -O -sS --top-ports 30 -PE -PP -PS21-23,25,53,80-81,110-111,113,135,139,143,199,443,445,465,548,587,993,995,1025,1720,1723,3306,3389,5900,6001,8080,8888
exitCode=$?
gzip debug.out
exit $exitCode
