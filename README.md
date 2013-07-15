magic-icmp
==========
This is a little daemon which listen to a network interface for ICMP6-PING request packages. 
Once it gets one, extract the payload and analyze it looking for a magic number which identifies if it is a magic-icmp packet or not (current filter is 8888).
In case it is an icmp magic, the next 2 bytes (4 hex numbers) specify the command-type and the last 4 bytes the data which will be given to the command executed.

```
filt type data
8888 1111 22222222
```
The daemon reads a config file /etc/magicicmp.conf which could look like:

```
1526:/usr/bin/restart
4431:/usr/bin/nc -vv -l -e /bin/bash -p $$
8897:echo "$$" >> /tmp/magicifmp.log
```

The first number is the command-type, the user can define its own types. The second is the command. 
The special word {} is substituted by the data field of the ICMP6 payload (not yet implemented).

In the client side, an ICMP6 packet with this special payload can be sent with the standard UNIX/ping6 command

```
ping6 -p 8888111122222222 ff02::1%eth0 -s 24
```

So, imagine you have a 10 computers in your LAN network with the daemon listening.
Would you like to reboot all of them imediatly? Just execute

```
ping6 -p 8888152600000000 ff02::1%eth0 -s 24
```

This is just an example, nice things could be achieved with this small system! It is up to your imagination.

Happy hacking! :)
