#!/bin/bash

make clean || { echo 'clean failed' ; exit 1; }
make || { echo 'make failed' ; exit 1; }
echo 'finished make'

sudo systemctl stop aesmd
wait
sudo /sbin/modprobe -r isgx
sudo rm -rf "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
sudo /sbin/depmod
sudo /bin/sed -i '/^isgx$/d' /etc/modules
echo 'removed old sgx driver'

sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
sudo cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"    
sudo /sbin/depmod
sudo /sbin/modprobe isgx
echo 'installed new sgx driver'

sudo systemctl start aesmd
