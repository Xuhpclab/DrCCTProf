#! /bin/bash

CUR_DIR=$(pwd)

rm -r debug_log
mkdir debug_log
mkdir debug_log/cct_logs
mkdir debug_log/dr_logs

cp -r logs/* debug_log/cct_logs/
cp -r build_debug/logs/* debug_log/dr_logs/

tar -jcvf debug_log.tar.bz2 debug_log
rm -r debug_log