#!/bin/sh

if [ -e "router.log" ]; then
    rm router.log
fi
./router start
sleep 1
tail -1cf router.log
