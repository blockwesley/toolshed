#!/bin/bash
# Bash Script to query some basic information about the host I am on.
# Wesley 2025

echo "The date today is: " `date`

#Print Some Basic Info About the Host and Setup
if [ -x "$(which hostname)" ]; then
    echo "Hostname of this machine is: " `hostname`
else
    echo "Unable to find hostname command aborting execution of script."
    exit 1
fi

#Print Some Basic Info About the Host and Setup
if [ -x "$(which free)" ]; then
    # $total_memory = 
    # total_memory = eval(`awk \'NR==2 {print $3}\'`)
    # MEMORY=$(free -m | awk 'NR==2{printf "%.2f%%\t\t", $3*100/$2 }')
    TOTAL_MEMORY=$(free -h | awk 'NR==2{print $2 }')
    USED_MEMORY=$(free -h | awk 'NR==2{print $3 }')
    FREE_MEMORY=$(free -h | awk 'NR==2{print $4 }')
    # DISK=$(df -h | awk '$NF=="/"{printf "%s\t\t", $5}')
    # CPU=$(top -bn1 | grep load | awk '{printf "%.2f%%\t\t\n", $(NF-2)}')
    echo "Memory Information (Total/Used/Free): $TOTAL_MEMORY / $USED_MEMORY / $FREE_MEMORY"
else
    echo "Unable to find memory command aborting execution of script."
    exit 1
fi

#Grep the cpuinfo file and determine if the host has hardware virtualization support
# REF : https://www.cyberciti.biz/faq/linux-xen-vmware-kvm-intel-vt-amd-v-support/
if [ -x "$(which grep)" ]; then
    grep -E -wo 'svm|vmx|lm|aes' /proc/cpuinfo  | sort | uniq \
    | sed -e 's/aes/Hardware encryption=Yes (&)/g' \
    -e 's/lm/64 bit cpu=Yes (&)/g' -e 's/svm/AMD hardware virtualization=Yes (&)/g' \
    -e 's/vmx/Intel hardware virtualization=Yes (&)/g'
else
    echo "Unable to determine virtualization support on this host."
    exit 1
fi