#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
void print_packet_header(const struct pcap_pkthdr *packet_header)
{
    char time_str[127];

    strftime(time_str, sizeof(time_str), "Date: %Y-%m-%d Time: %H:%M:%S", localtime(&(packet_header->ts)));
    printf("Time: %s.%.6ld\n", time_str, packet_header->ts.tv_usec);
    printf("Captured length:%d\n", packet_header->caplen);
    printf("Actual length:%d\n", packet_header->len);
}

int get_packet_type(const uint8_t *buffer, int buflen)
{

    static int pktNum = 0;
    printf("Packet Number:%d\n", ++pktNum);
    struct ethhdr *eth = (struct ethhdr *)(buffer);
    printf("Payload protocol    : 0x%04X\n", ntohs(eth->h_proto));
    if (ntohs(eth->h_proto) != 0x0800)
    {
        return eth->h_proto;
    }
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct protoent *protocol;
    if ((protocol = getprotobynumber(ip->protocol)) != NULL)
    {
        printf("Ip Packet protocol     : %s\n", protocol->p_name);
    }
    return ip->protocol;
}

int icmp_count = 0;
int tcp_count = 0;
int udp_count = 0;
int arp_count = 0;
int other_count = 0;
void packetHandler(uint8_t *userData, const struct pcap_pkthdr *packet_header, const u_char *packet)
{
    printf("\n");
    int packet_type = get_packet_type(packet, packet_header->len);
    if (1 == packet_type)
        icmp_count++;
    else if (17 == packet_type)
        udp_count++;
    else if (6 == packet_type)
        tcp_count++;
    else if (0x0806 == ntohs(packet_type))
        arp_count++;
    else
    {
        other_count++;
    }
    print_packet_header(packet_header);
    printf("\n");
}
int main(int argc, char **argv)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    int i, maxCountSyn = 0, maxCountHttp = 0, maxIdxSyn = 0, maxIdxHttp = 0;
    char *inputFile = "pcap_file/dump.pcap";
    if (argc > 1)
    {
        inputFile = argv[1];
    }
    printf("Analyzing file: %s\n", inputFile);
    fp = pcap_open_offline(inputFile, errbuf);
    if (fp == NULL)
    {
        fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
        return 0;
    }
    printf("Majon ver: %d\nMinor Version: %d\nLink Type: %d\n", pcap_major_version(fp), pcap_minor_version(fp), pcap_datalink(fp));
    if (pcap_loop(fp, 0, packetHandler, NULL) < 0)
    {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        return 0;
    }
    printf("ARP packets: %d, ICMP packets: %d, TCP packets: %d, UDP packets: %d, others: %d\n", arp_count, icmp_count, tcp_count, udp_count, other_count);
    pcap_close(fp);
}