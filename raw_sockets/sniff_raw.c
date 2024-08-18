#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h> // for ethernet header
#include <netinet/ip.h>		  // for ip header
#include <netinet/tcp.h>
#include <arpa/inet.h>

void data_process(unsigned char *buffer, int buflen)
{

	static int pktNum = 0;
	struct ethhdr *eth = (struct ethhdr *)(buffer);

	printf("\nEthernet Header for packet number %d\n", pktNum++);
	printf("\t|-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	// https://en.wikipedia.org/wiki/EtherType
	printf("\t|-Payload protocol    : 0x%04X\n", ntohs(eth->h_proto));
	if (ntohs(eth->h_proto) == 0x0800)
	{
		struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

		static struct sockaddr_in source, dest;
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = ip->saddr;
		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = ip->daddr;
		struct protoent *protocol;
		if ((protocol = getprotobynumber(ip->protocol)) == NULL)
		{
			printf("1.2.3.4 Unhandled IP Protocol Type:%d Exiting!!!!\n", ip->protocol);
			exit(2);
		}
		printf("\n\tIP Header\n");
		printf("\t\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
		printf("\t\t|-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
		printf("\t\t|-Protocol          : %s\n", protocol->p_name);
	}
}

int main()
{

	int sock_r, saddr_len, buflen;
	struct sockaddr saddr;
	unsigned char *buffer = (unsigned char *)malloc(65536);
	memset(buffer, 0, 65536);

	printf("starting .... \n");

	sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_r < 0)
	{
		printf("error in socket\n");
		return -1;
	}

	while (1)
	{
		saddr_len = sizeof(saddr);
		buflen = recvfrom(sock_r, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);

		if (buflen < 0)
		{
			printf("error in reading recvfrom function\n");
			return -1;
		}
		data_process(buffer, buflen);
	}

	close(sock_r);
}
