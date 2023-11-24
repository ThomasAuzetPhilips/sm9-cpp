#!/bin/bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2 -out sm2key.pem
