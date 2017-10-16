#include <net/ethernet.h>
#include <netinet/ether.h>

#include "headerReader.h"



int getEthernet(const u_char *bytes, bpf_u_int32 dataLength, libnet_t *l)
{
  printf("\n--------------- ETHERNET ---------------\n\n");

  struct ether_header *headerEthernet = (struct ether_header *) bytes;
  
  //printf("MAC Destination:  %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_dhost));
  //printf("MAC Source: %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_shost));
  //printf("Ether Type: 0x%04x\n", ntohs(headerEthernet->ether_type));  

  switch(ntohs(headerEthernet->ether_type))
  {
    case ETHERTYPE_IP:
      getIp(bytes + sizeof(*headerEthernet), dataLength - sizeof(*headerEthernet), l, headerEthernet->ether_shost);
      break;
      
    case ETHERTYPE_ARP:
      getArp(bytes + sizeof(*headerEthernet), dataLength - sizeof(*headerEthernet), l);
      break;
  }
}
