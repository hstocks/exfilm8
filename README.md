#exfilm8

##Command and control commands
| Command       | Description   |
|:------------- |:--------------|
| rempwd | Print the current directory |
| remls | List files in the current directory |
| remcd <path> | Change the current directory |
| showopts | Display a list of available options and values |
| setopt <option> <value> | Set an option |
| exfil [-s \| -f \| -p <n>] [-m \| -i \| -d] filename | Start exfiltration of specified file |
| exit, quit, close | Close exfilm8 |

##Exfil options
| Option       | Description   |
|:-------------|:--------------|
| -s | Stealth mode, default |
| -p <no. per second> | Packets Per Second mode |
| -f | Fast mode |
| -m | Send DNS and ICMP packets, default |
| -d | Send DNS packets only |
| -i | Send ICMP packets only |

##How to run
1. python3 client.py
2. python3 server.py

Exfiltrated files will be put in to the directory specified in 'outputDirectory' option

