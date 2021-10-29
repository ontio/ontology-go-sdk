#!/bin/bash
# code from https://github.com/Seklfreak/Robyul2
unset dirs files
dirs=$(go list ./... | grep -v vendor/ | grep -v ontology-crypto$)
set -x -e

wget -c https://github.com/ontio/ontology/releases/download/v1.14.1-alpha/ontology-linux-amd64 -O ontology
chmod +x ontology
echo -e "123456\n123456\n" | ./ontology account add -d
echo -e "123456\n" | nohup  ./ontology --testmode --testmode-gen-block-time 10 > /dev/null 2>&1 &
# wait test ontology ready
sleep 10

for d in $dirs
do
  go test -v $d
done

pkill ontology
