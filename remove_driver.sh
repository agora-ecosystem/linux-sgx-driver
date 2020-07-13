#!/bin/bash

sudo systemctl stop aesmd
wait
sudo /sbin/modprobe -r isgx
sudo rm -rf "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
sudo /sbin/depmod
sudo /bin/sed -i '/^isgx$/d' /etc/modules
sudo systemctl start aesmd
echo 'removed old sgx driver'
