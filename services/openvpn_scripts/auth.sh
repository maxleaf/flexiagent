#!/bin/bash

username=$(head -n 1 $1)
password=$(cat $1 | head -2 | tail -1)

url="https://localvpn.flexiwan.com:4443/api/auth/tokens/verify?username=${username}"

response=$(curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${password}" -d @/etc/flexiwan/agent/fwagent_info.txt --insecure --write-out '%{http_code}' --silent --output /dev/null $url)

if [[ "$response" -ne 200 ]] ; then
  exit 1
else
  exit 0
fi