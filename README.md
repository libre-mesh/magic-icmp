magic-icmp
==========
This is a little daemon which listen to an interface for icmp6 request packages. 
Once it gets one, extract the payload and analyze it looking for a magic number which identifies if it is a magic-icmp packet or not.
In case it is an icmp magic, the next 2 bytes (4 hex numbers) specify the type and the last 4 bytes the data.

filt type data
0000 1111 22222222

This packet can be send with the next standard ping6 command

ping6 -p 0000111122222222 ff02::1%eth0 -s 24


In the other side the daemon reads a config file /etc/magicicmp.conf which could look like:

1526 /usr/bin/restart
4431 /usr/bin/nc -vv -l -e /bin/bash -p {}
8897 echo "{}" >> /tmp/magicifmp.log

The first number is the type, the user can define its own types. The second is the command. 
The special word {} is substituted by the data field of the icmp6 payload.

Happy hacking! :)
