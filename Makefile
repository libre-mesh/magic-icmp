CC:=gcc
CP:=cp -f

default:
	$(CC) -lpcap -o micmp micmp.c	

install: default
	$(CP) magicicmp.conf /etc/magicicmp.conf
	$(CP) micmp /usr/bin/micmp 
