#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <asm-generic/socket.h>
#include <arpa/inet.h>

int main(int argc, char const *argv[])
{
  char buffer[sizeof(struct iphdr)] = {0};
  struct iphdr *ip = (struct iphdr *)buffer;

  // https://man7.org/linux/man-pages/man7/socket.7.html
  //  create an ip raw socket with RAW protocol
  int sock_raw = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock_raw < 0)
  {
    perror("socket() error");
    exit(2);
  }
  printf("Raw socket is created.\n");

  // inform the kernel do not fill up the packet structure, we will build our own
  // not actually needed as this is set when using IPPROTO_RAW
  // const int on = 1;
  // if (setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
  // {
  //   perror("setsockopt() error");
  //   exit(2);
  // }

  // fabricate the relevant IP header fields
  ip->tot_len = sizeof(struct iphdr);
  ip->protocol = 17; // UDP
  // source and destination IP addresses, can use spoofed address here
  ip->saddr = inet_addr("1.2.3.4");
  ip->daddr = inet_addr("1.8.0.8");

  // set destination address so kernel can populate ethernet header.
  struct sockaddr_in sadr_in = {AF_INET, 0, inet_addr("192.168.50.1"), 0};

  if (sendto(sock_raw, buffer, ip->tot_len, 0, (struct sockaddr *)&sadr_in, sizeof(sadr_in)) < 0)
  {
    perror("sendto()");
    exit(3);
  }
  printf("OK: one packet is sent.\n");

  close(sock_raw);
  return 0;
}