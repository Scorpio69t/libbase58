#!/bin/sh
hex=$(base58-cli -d 50 19DXstMaV43WpYg4ceREiiTv2UntmoiA9j | xxd -p)
test x$hex = x005a1fc5dd9e6f03819fca94a2d89669469667f9a074655946
if [ $? -ne 0 ]; then
    echo "FAIL: base58 decode"
    exit 1
fi
echo "PASS: base58 decode"
exit 0