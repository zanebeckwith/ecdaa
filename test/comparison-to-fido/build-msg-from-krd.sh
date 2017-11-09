#!/bin/bash

appId="$1"
krd_file="$2"
output_file="$3"

echo -n $appId > $output_file
sha256sum $krd_file | cut -d ' ' -f 1 | xxd -ps -r >> $output_file
