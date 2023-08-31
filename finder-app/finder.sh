#!/bin/bash

filesdir=$1
searchstr=$2

echo $filesdir
echo $searchstr

if [[ $# -ne 2 ]]; then
   exit 1
fi

if [[ ! -d $filesdir ]]; then
    exit 1
fi

count=$(ls -1 ${filesdir} | wc -l)
matches=$(grep -ri "${searchstr}" ${filesdir} | wc -l)

echo "The number of files are ${count} and the number of matching lines are ${matches}"