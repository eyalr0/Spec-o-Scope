#!/bin/sh

echo Setting up frequency state
sudo cpupower -c all frequency-set -g performance
sudo cpupower -c all frequency-set -d 3400000
sudo cpupower -c all frequency-set -u 3400000

echo Setting up huge pages
sudo hugeadm --pool-pages-min 2MB:24

./info.sh