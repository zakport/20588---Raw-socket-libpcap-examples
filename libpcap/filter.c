#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

int get_packet_type(const uint8_t *buffer, int buflen)
{

    static int pktNum = 0;
    struct ethhdr *eth = (struct ethhdr *)(buffer);
    if (ntohs(eth->h_proto) != 0x0800)
    {
        return eth->h_proto;
    }
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    return ip->protocol;
}
// https://www.tcpdump.org/pcap.html
int main(int argc, char *argv[])
{
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i = 0;
    if (argc > 1)
    {
        device = argv[1];
    }
    else
    {
        if (pcap_findalldevs(&interfaces, error_buffer) == -1)
        {
            printf("\nerror in pcap findall devs%s\n", error_buffer);
            return -1;
        }
        device = interfaces->name;
    }
    /* Open device for live capture */
    int promisc = 0;
    int timeout_limit = 1000; /* In milliseconds */
    pcap_t *handle = pcap_open_live(
        device,
        BUFSIZ,
        promisc,
        timeout_limit,
        error_buffer);
    if (handle == NULL)
    {
        printf("pcap_open_live(): %s\n", error_buffer);
        exit(1);
    }
    printf("Capturing on device: %s\n", device);

    // verify that our device provides the headers we are looking for
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
        return (2);
    }

    bpf_u_int32 mask; /* The netmask of our sniffing device */
    bpf_u_int32 net;  /* The IP of our sniffing device */

    if (pcap_lookupnet(device, &net, &mask, error_buffer) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
    }
    struct bpf_program fp;            /* The compiled filter expression */
    char *filter_exp = "tcp or icmp"; /* The filter expression */
    if (argc > 2)
    {
        filter_exp = argv[2];
    }
    printf("Filtering all but %s packets\n", filter_exp);
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    const uint8_t *packet;
    struct pcap_pkthdr *packet_header;
    struct pcap_stat stats;
    int icmp_count = 0;
    int other = 0;
    while (1)
    {
        /* Attempt to capture one packet. If there is no network traff\ic
         and the timeout is reached, it will return NULL */
        int ret = pcap_next_ex(handle, (&packet_header), &packet);
        if (-1 == ret)
        {
            pcap_perror(handle, error_buffer);
            printf("No packet found.\n");
            return 2;
        }
        if (1 == get_packet_type(packet, packet_header->len))
            icmp_count++;
        else
        {
            other++;
        }

        /* Our function to output some info */
        // print_packet_info(packet, *packet_header);
        // free(packet_header);
        if (0 != pcap_stats(handle, &stats))
        {
            perror("stats errror\n");
        }
        printf("pcap stats, received: %d, dropped: %d, ICMP count: %d\n", stats.ps_recv, stats.ps_drop + stats.ps_ifdrop, icmp_count);
        fflush(stdout);
    }

    pcap_close(handle);
    return 0;
}