# exfilm8

Command and control commands
=============================
rempwd 												– Print the current directory
remls												– List files in the current directory
remcd <path>										– Change the current directory
showopts 											– Display a list of available options and values
setopt <option> <value>								– Set an option
exfil [-s | -f | -p <n>] [-m | -i | -d] filename 	– Start exfiltration of specified file

Exfil options
==============
-s						- Stealth mode, default
-p <no. per second>	- Packets Per Second mode
-f 						- Fast mode
-m						- Send DNS and ICMP packets, default
-d						- Send DNS packets only
-i						- Send ICMP packets only


How to run
===========
python3 client.py
python3 server.py

I don't think you need to use sudo, can't remember and cba to start VM.

Files will be put in to directory 'output' directory

