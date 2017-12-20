#!/bin/bash

# Simple test for fcrypt (CS 4740/6740: Network Security)
# Amirali Sanatinia (amirali@ccs.neu.edu)

python fcrypt.py -e receiver_public_key.der sender_private_key.pem test.txt output.txt
python fcrypt.py -d receiver_private_key.pem sender_public_key.der output.txt finalop.txt

if ! diff -q test.txt finalop.txt > /dev/null ; then
  echo "FAIL"
  else echo "PASS!"
fi
