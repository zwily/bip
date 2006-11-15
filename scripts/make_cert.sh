#!/bin/sh

openssl req -new -x509 -days 365 -nodes \
        -config make_cert.cnf -out bip.pem -keyout bip.pem
#RANDOM_FILE=/dev/urandom
#openssl gendh -rand $(RANDOM_FILE) 512 >> bip.pem
#openssl gendh 512 >> bip.pem
openssl x509 -subject -dates -fingerprint -noout -in bip.pem
