#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define CONFIG "/etc/magicicmp.conf"

static const char *filter = "icmp6";

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
	unsigned char filter[2];
	unsigned char type[2];
	unsigned char data[4];
};

struct sconfig {
	char type[2];
	char command[64];
};

#define NEXT(n, e, type) \
	do { \
		if ((n + sizeof(type)) > e) { \
			if (0) printf("TOO SHORT! " #type " %lu + %lu > %lu\n", n, sizeof(type), e); \
			return; \
		} \
		n += sizeof(type); \
	} while(0)

static const char * print_ether(struct ether_packet *e)
{
	printf("src %02x:%02x:%02x:%02x:%02x:%02x "
	       "dst %02x:%02x:%02x:%02x:%02x:%02x ",
	       e->src[0], e->src[1], e->src[2], e->src[3], e->src[4], e->src[5],
	       e->dst[0], e->dst[1], e->dst[2], e->dst[3], e->dst[4], e->dst[5]);
}

static void print_ipv6(struct ipv6_packet *i)
{
	char buf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &i->src, buf, sizeof(buf));
	printf("src %s ", buf);

	inet_ntop(AF_INET6, &i->dst, buf, sizeof(buf));
	printf("dst %s ", buf);
}

static void packet_cb(unsigned char *args, const struct pcap_pkthdr *header,
		const unsigned char *packet)
{
	void *next = (void *)packet;
	void *end = next + header->caplen;
	struct ether_packet *e;
	struct ether_qtag *q;
	struct icmp_packet *i;

	//printf("Got pkt %lu.%lu %u/%u ",
	 //      header->ts.tv_sec, header->ts.tv_usec, header->caplen, header->len);

	e = next;
	NEXT(next, end, struct ether_packet);
	//print_ether(e);

	if (e->type == 0x8100)
	{
		q = next;
		NEXT(next, end, struct ether_qtag);
		//printf("vlan %u/%u/%u ", q->pcp, q->dei, q->vid);
	}

	//print_ipv6(next);
	NEXT(next, end, struct ipv6_packet);

	i = next;
	NEXT(next, end, struct icmp_packet);
	//printf("icmp6 %u/%u ", i->type, i->code);

	if (i->type != 128 && i->type != 129)
		return;

	unsigned char *payload = next;
	int n,j;
	struct magic_icmp m;
	
	j=0;
	for (n = 8; n <= 10; n++) {
		m.filter[j] = payload[n];
		j++;
		}
	j=0;
	for (n = 10; n <= 12; n++) {
		m.type[j] = payload[n];
		j++;
		}
	j=0;
	for (n = 12; n <= 16; n++) {
		m.data[j] = payload[n];
		j++;
		}
		
	printf("\n");
	printf("%lu", header->ts.tv_sec);
	printf(" Filter: %02x%02x", m.filter[0],m.filter[1]);
	printf(" Type: %02x%02x", m.type[0],m.type[1]);
	printf(" Data: %02x%02x%02x%02x", m.data[0],m.data[1],m.data[2],m.data[3]);
	printf("\n");
}

static void readconfig(struct sconfig *buf) {
	char c = '1';
	int i = 0, j = 0;
	int fd = open(CONFIG,O_RDONLY);
	
	printf("\nLoading config file at %s", CONFIG);
	if (fd) {	
		while( c != EOF ) {
			
			read(fd,&c,sizeof(char));
			printf("\n-> %c", c);
			
			/*if ( c == '\n' ) {
				++i;
				j = 0;
			}
			else {
				buf[i].command[j] = c;
				++j;
			}*/
		}	
		close(fd);
	}
	else printf("Cannot open config file");
}
	
int main(int argc, char **argv)
{
	const char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int rv;

	pcap_t *session;
	struct bpf_program fp;

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <device>\n", argv[0]);
		return 1;
	}

	dev = argv[1];
	struct sconfig config[64];
	
	readconfig(config);
	
	printf("\nInstruction loaded: %s", config[0].command);
	
	session = pcap_open_live(dev, 1500, 0, 100, errbuf);

	if (!session)
	{
		fprintf(stderr, "Can't open %s for capturing: %s\n", dev, errbuf);
		return 2;
	}

	if (pcap_compile(session, &fp, filter, 0, 0) == -1)
	{
		fprintf(stderr, "Can't parse filter %s: %s\n", filter, pcap_geterr(session));
		return 3;
	}

	if (pcap_setfilter(session, &fp) == -1)
	{
		fprintf(stderr, "Can't install filter %s: %s\n", filter, pcap_geterr(session));
		return 4;
	}

	rv = pcap_loop(session, -1, packet_cb, NULL);

	if (rv)
		fprintf(stderr, "Capture loop terminated with code %d\n", rv);

	pcap_close(session);

	return rv;
}
