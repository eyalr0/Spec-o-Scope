#!/bin/sh

echo ======= Frequency Info
sudo cpupower -c all frequency-info | grep -E --color=never "(analyzing CPU)|(current policy)|(The governor)|(current CPU frequency)"

echo ======= Huge Pages Info
hugeadm --pool-list

echo "======= Prefetcher State (0=Enabled, f=Disabled)"
sudo rdmsr -a 0x1a4