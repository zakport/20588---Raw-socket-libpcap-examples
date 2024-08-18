#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>

#include <linux/if_packet.h>

#include <net/if.h>
#include <arpa/inet.h>

#define PKT_SIZE (sizeof(struct iphdr) + sizeof(struct ethhdr))

int main(int argc, char **argv)
{

	// set your interface name here
	char *interface = "wlp0s20f3";
	int protocolnum = 17;
	if (argc > 1)
	{
		protocolnum = atoi(argv[1]);
	}

	// https://man7.org/linux/man-pages/man7/socket.7.html
	//  create an ip raw socket with RAW protocol
	int sock_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw < 0)
	{
		perror("socket() error");
		exit(2);
	}
	printf("Raw socket is created.\n");

	char *buffer = (unsigned char *)malloc(PKT_SIZE);
	if (buffer == NULL)
	{
		perror("buffer alloc");
		exit(1);
	}
	memset(buffer, 0, PKT_SIZE);

	unsigned int interfaceNum = if_nametoindex(interface);
	if (!interfaceNum)
	{
		perror("if_nametoindex");
		exit(1);
	}

	printf("interface [%s] has index : %d\n", interface, interfaceNum);
	// https://man7.org/linux/man-pages/man7/packet.7.html

	printf("ethernet packaging start ... \n");

	struct ethhdr *eth = (struct ethhdr *)(buffer);
	eth->h_source[0] = 0x1;
	eth->h_source[1] = 0x2;
	eth->h_source[2] = 0xFA;
	eth->h_source[3] = 0xCE;
	eth->h_source[4] = 0x5;
	eth->h_source[5] = 0x6;

	eth->h_dest[0] = 0x00;
	eth->h_dest[1] = 0x18;
	eth->h_dest[2] = 0x08;
	eth->h_dest[3] = 0x20;
	eth->h_dest[4] = 0x24;
	eth->h_dest[5] = 0x00;

	eth->h_proto = htons(ETH_P_IP); // 0x800

	printf("ethernet packaging done.\n");

	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

	iph->protocol = protocolnum;
	iph->saddr = inet_addr("1.2.3.4");
	iph->daddr = inet_addr("1.1.1.1");
	iph->tot_len = PKT_SIZE;

	struct sockaddr_ll sadr_ll = {0, 0, interfaceNum, 0, 0, 0, 0};

	int send_len = sendto(sock_raw, buffer, iph->tot_len + sizeof(struct ethhdr), 0, (const struct sockaddr *)&sadr_ll, sizeof(struct sockaddr_ll));
	if (send_len < 0)
	{
		perror("");
		printf("error in sending....sendlen=%d....errno=%d\n", send_len, errno);
		return -1;
	}
	close(sock_raw);
	return 0;
}
