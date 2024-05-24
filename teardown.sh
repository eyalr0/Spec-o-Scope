#!/bin/sh


echo Restoring frequency state
sudo cpupower -c all frequency-set -g powersave
sudo cpupower -c all frequency-set -d 400000
sudo cpupower -c all frequency-set -u 3400000

echo Restoring prefetcher MSR
sudo wrmsr -a 0x1a4 0

./info.sh
