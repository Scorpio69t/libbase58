#!/bin/sh
b58=$(echo '005a1fc5dd9e6f03819fca94a2d89669469667f9a074655946' | xxd -r -p | base58-cli)
test x$b58 = x19DXstMaV43WpYg4ceREiiTv2UntmoiA9j
if [ $? -ne 0 ]; then
    echo "FAIL: base58 encode"
    exit 1
fi
echo "PASS: base58 encode"
exit 0