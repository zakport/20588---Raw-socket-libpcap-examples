#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

// https://www.tcpdump.org/pcap.html
int main(int argc, char *argv[])
{
    char *device = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];

    // Se
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i = 0;

    int capNum = 100;
    if (argc > 1)
    {
        capNum = atoi(argv[1]);
    }
    if (argc > 2)
    {
        device = argv[2];
    }
    // not in use, currently capture on all devices if not specified
    else
    {

     if (pcap_findalldevs(&interfaces, error) == -1)
     {
         printf("\nerror in pcap findall devs");
         return -1;
     }
     device = interfaces->name;
    }
    /* Open device for live capture */
    int promisc = 0;
    int timeout_limit = 1000; /* In milliseconds */
    pcap_t *handle;
    handle = pcap_open_live(
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
    if (device == NULL)
    {
        printf("Capturing on all devices\n");
    }
    else
    {
        printf("Capturing on device: %s\n", device);
    } // int *dlt_buf;
    // int num =
    //     pcap_list_datalinks(handle, &dlt_buf);
    // for (int i = 0; i < num; i++)
    // {
    //     printf("%s\n", pcap_datalink_val_to_description(dlt_buf[i]));
    // }
    // // verify that our device provides the headers we are looking for
    // if (pcap_datalink(handle) != DLT_EN10MB)
    // {
    //     fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
    //     return (2);
    // }

    pcap_dumper_t *dumper;
    char *outputFileName = "pcap_file/dump.pcap";
    if ((dumper = pcap_dump_open(handle, outputFileName)) == NULL)
    {
        perror("Couldn't open dumper\n");
    }
    if (pcap_loop(handle, capNum, &pcap_dump, (char *)dumper) != 0)
    {
        printf("Failed reading file\n");
        return 2;
    }
    printf("Saved %d packets to file: \"%s\"", capNum, outputFileName);
    pcap_dump_close(dumper);

    pcap_close(handle);
    return 0;
}