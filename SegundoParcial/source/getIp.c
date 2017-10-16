#include <netinet/ip.h>
#include <netinet/in.h>

#include "headerReader.h"


int getIp(const u_char *bytes, bpf_u_int32 dataLength, libnet_t *l, uint8_t *macSource)
{
  uint32_t ip = 0xC0A80114;

  printf("\n------------------ IP ------------------\n\n");
  
  struct iphdr *headerIP = (struct iphdr *) bytes;
  
  if ((headerIP->protocol == IPPROTO_ICMP) && (ntohl(headerIP->daddr) == ip))
  {
    printf("ICMP received.\n");
    //getICMP(bytes + headerIP -> ihl * 4, dataLength - (headerIP->ihl*4), l, macSource, headerIP->saddr, headerIP->daddr);
  }

  /*
  printf("Version: %u\n", headerIP->ip_v);
  printf("Internet Header Length: %u\n", headerIP->ip_hl);
  printf("Type Of Service: %u\n", headerIP->ip_tos);
  printf("Total Length: %u\n", ntohs(headerIP->ip_len));
  printf("Identification: %u\n", ntohs(headerIP->ip_id));
  printf("Flags:\n");
  if ((headerIP->ip_off & 0xD000) & IP_DF)
    printf("\tDon't Fragment\n");
  else
    printf("\tMay Fragment\n");
  if ((headerIP->ip_off & 0xD000) & IP_MF)
    printf("\tMore Fragments\n");
  else
    printf("\tLast Fragment\n");   
  printf("Fragment Offset: %u\n", headerIP->ip_off & IP_OFFMASK);
  printf("Time To Live: %u\n", headerIP->ip_ttl);
  printf("Protocol: %u\n", headerIP->ip_p);
  printf("Header Checksum: %u\n", headerIP->ip_sum);
  printf("Source Address:   %s\n", inet_ntoa(headerIP->ip_src));
  printf("Destination Address:  %s\n", inet_ntoa(headerIP->ip_dst));*/

  
}
