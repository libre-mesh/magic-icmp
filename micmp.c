/*
    Copyright (C) 2013 Pau Escrich

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#define CONFIG "/etc/magicicmp.conf"
#define MYFILTER "8888"
#define TYPESIZE 5
#define FILTERSIZE 5
#define DATASIZE 9
#define CMDSIZE 256
#define CFGSIZE 64

// LibpCap Filter
static const char *lc_filter = "icmp6";

struct ether_qtag {
	uint16_t pcp:3;
	uint16_t dei:1;
	uint16_t vid:12;
};

struct ether_packet {
	unsigned char src[6];
	unsigned char dst[6];
	uint16_t type;
};

struct ipv6_packet {
	uint32_t version:4;
	uint32_t tos:8;
	uint32_t flow:20;
	uint16_t length;
	uint8_t nexthdr;
	uint8_t hoplimit;
	struct in6_addr src;
	struct in6_addr dst;
};

struct icmp_packet {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t id;
	uint16_t seq;
	unsigned char garbage[8];
};

struct magic_icmp {
	unsigned char filter[FILTERSIZE];
	unsigned char type[TYPESIZE];
	unsigned char data[DATASIZE];
};

struct sconfig {
	unsigned char type[TYPESIZE];
	char command[CMDSIZE];
};

//Global config struct
struct sconfig config[CFGSIZE];

#define NEXT(n, e, type) \
	do { \
		if ((n + sizeof(type)) > e) { \
			if (0) printf("TOO SHORT! " #type " %lu + %lu > %lu\n", n, sizeof(type), e); \
			return; \
		} \
		n += sizeof(type); \
	} while(0)

static const char * print_ether(struct ether_packet *e) {
	printf("src %02x:%02x:%02x:%02x:%02x:%02x "
	       "dst %02x:%02x:%02x:%02x:%02x:%02x ",
	       e->src[0], e->src[1], e->src[2], e->src[3], e->src[4], e->src[5],
	       e->dst[0], e->dst[1], e->dst[2], e->dst[3], e->dst[4], e->dst[5]);
}

static void print_ipv6(struct ipv6_packet *i) {
	char buf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &i->src, buf, sizeof(buf));
	printf("src %s ", buf);
	inet_ntop(AF_INET6, &i->dst, buf, sizeof(buf));
	printf("dst %s ", buf);
}

static int scommand(struct sconfig *cfg, char *type) {
	int i;
	for(i=0; cfg[i].type[0] != '\0'; ++i)
		if( strncmp(cfg[i].type,type,TYPESIZE-1) == 0 )
			return i;
	return -1;
}

static void exec_cmd(int ic, char *d) {
	int c;
	char command[CMDSIZE+DATASIZE];
	unsigned char dkey = 0;
	
	// Looking for special word $$ to substitute it by <data>
	for (c=0; config[ic].command[c] != '\0'; ++c) {
		if (config[ic].command[c] == '$') {
			if (dkey == 0) dkey = 1;
			else if (dkey == 1) {
				strncpy(command,config[ic].command,c-1);
				strcat(command,d);
				if (config[ic].command[c+1] != '\0')
					strcat(command,&config[ic].command[c+1]);
				break;
			}
		}
		else if (dkey == 1) dkey = 0;
	}
	printf(" Executing: %s\n",command);
	system(command);
}

static void packet_cb(unsigned char *args, const struct pcap_pkthdr *header,
		const unsigned char *packet) {
	void *next = (void *)packet;
	void *end = next + header->caplen;
	int ic;
	struct ether_packet *e;
	struct ether_qtag *q;
	struct icmp_packet *i;

	//printf("Got pkt %lu.%lu %u/%u ",
	//      header->ts.tv_sec, header->ts.tv_usec, header->caplen, header->len);

	e = next;
	NEXT(next, end, struct ether_packet);

	if (e->type == 0x8100){
		q = next;
		NEXT(next, end, struct ether_qtag);
		//printf("vlan %u/%u/%u ", q->pcp, q->dei, q->vid);
	}

	NEXT(next, end, struct ipv6_packet);
	i = next;
	NEXT(next, end, struct icmp_packet);
	//printf("icmp6 %u/%u ", i->type, i->code);

	if (i->type != 128 && i->type != 129)
		return;

	unsigned char *payload = next;
	int n,j;
	struct magic_icmp m;
	
	// set 8,9 bytes for filter
	sprintf(m.filter,"%02x%02x\0",payload[8],payload[9]);
	
	// only if the filter match the following data is processed
	if(strncmp(MYFILTER,m.filter,FILTERSIZE-1) == 0) {
		// set 10,11 bytes for type	
		sprintf(m.type,"%02x%02x\0",payload[10],payload[11]);
		
		// set 12,13,14,15 bytes for arbitrary data
		sprintf(m.data,"%02x%02x%02x%02x\0",payload[12],payload[13],payload[14],payload[15]);
		
		// some debug information
		printf("\n[%lu] Magic-ICMP received\n ", header->ts.tv_sec);
		print_ether(e);
		printf("\n Type: %s |", m.type);
		printf(" Data: %s\n", m.data);
		
		ic = scommand(config,m.type);
		if ( ic >= 0 ) {
			printf(" Command found:");
			printf(" %s\n",config[ic].command);
			exec_cmd(ic,m.data);
		}
		else
			printf(" Command not found for %s\n", m.type);
	}
}

static void readconfig(struct sconfig *buf) {
	FILE *fd = fopen(CONFIG,"r");
	int linenum=0;
	printf("Loading config file %s\n", CONFIG);
	if (fd) {	
		char type[TYPESIZE];
		char c;
		char line[CMDSIZE+TYPESIZE+1];
		int i;
		unsigned char j,k,isType;
		
		while(fgets(line, CMDSIZE+TYPESIZE+1, fd) != NULL) {
			if(line[0] == '#') continue;
			j=0; k=0; 
			isType=1;
			while(c = line[j++]) {
				if (c == '\n' || c == '\0') break;
				if (isType && c == ':') { 
					buf[linenum].type[k] = '\0';
					isType = 0;
					k=0;
					continue; 
				}
				if (isType)  type[k] = c;
				if (!isType) buf[linenum].command[k] = c;
				++k;
			}
			
			buf[linenum].command[k] = '\0';
			type[TYPESIZE-1] = '\0';
			
			if (!isType) {
				for(i=0; i<TYPESIZE; ++i) buf[linenum].type[i] = type[i];
				printf("Recorded command %s -> %s\n",buf[linenum].type, buf[linenum].command);
				++linenum;
			}
		}
		fclose(fd);
	}
	else printf("Cannot open config file\n");
	
	buf[linenum].type[0] = '\0';
}
	
int main(int argc, char **argv) {
	const char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int rv;

	pcap_t *session;
	struct bpf_program fp;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <device>\n", argv[0]);
		return 1;
	}

	dev = argv[1];
	readconfig(config);
	printf("Ready to receive magic-icmp packets!\n");
	session = pcap_open_live(dev, 1500, 0, 100, errbuf);

	if (!session) {
		fprintf(stderr, "Can't open %s for capturing: %s\n", dev, errbuf);
		return 2;
	}
	if (pcap_compile(session, &fp, lc_filter, 0, 0) == -1) {
		fprintf(stderr, "Can't parse filter %s: %s\n", lc_filter, pcap_geterr(session));
		return 3;
	}
	if (pcap_setfilter(session, &fp) == -1) {
		fprintf(stderr, "Can't install filter %s: %s\n", lc_filter, pcap_geterr(session));
		return 4;
	}

	rv = pcap_loop(session, -1, packet_cb, NULL);
	if (rv)	fprintf(stderr, "Capture loop terminated with code %d\n", rv);
	pcap_close(session);

	return rv;
}
