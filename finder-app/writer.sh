#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Not all arguments is specified"
    exit 1
fi

writefile=$1
writestr=$2

path=$(dirname $writefile)

mkdir -p $path
touch $writefile

if [[ $? -ne 0 ]]; then
    echo "The file could not be created"
    exit 1
fi

echo $writestr > $writefile