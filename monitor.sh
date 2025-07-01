#!/bin/bash

source /etc/pakhsheshkon/server.conf

while true; do
    active_users=$(ss -t | grep ESTAB | wc -l)
    bandwidth=$(vnstat --oneline | cut -d';' -f 11)
    curl -X POST -d "server_code=$UNIQUE_CODE&users=$active_users&bandwidth=$bandwidth" http://iran-server-ip/monitor.php
    sleep 300
done
