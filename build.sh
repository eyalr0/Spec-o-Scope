#!/bin/bash

set -e
cd $(dirname $0)

if [[ $1 == "clean" ]]
then
    cmake --build build --target=clean
else
    cmake -B build -G Ninja
    cmake --build build
fi

