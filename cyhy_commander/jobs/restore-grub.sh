#!/bin/sh
env-update
source /etc/profile
grub-install --no-floppy /dev/sda
exit
