#include <stdlib.h>
#include <stdio.h>
#include <libnet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void buildArp(uint8_t *macDest, uint8_t *ipDest, uint8_t *ipSource, libnet_t *l)
{
	char *ghostMAC = "aa:bb:cc:dd:ee:ff";
	//uint8_t mac_broadcast_addr[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	int bytesWritten;

	struct ether_addr *MAC = ether_aton(ghostMAC);
	/*struct in_addr *myIpStruct;
	inet_aton(ip, myIpStruct);*/

	//BUILDING ARP:

	if (libnet_autobuild_arp (ARPOP_REPLY, MAC->ether_addr_octet, ipSource, macDest, ipDest, l) == -1)
  	{
    	fprintf(stderr, "Error building ARP header: %s\n",libnet_geterror(l));
    	
    	libnet_destroy(l);
    	exit(EXIT_FAILURE);
  	}


  	//BULDING ETHERNET:

  	if (libnet_build_ethernet (macDest, MAC->ether_addr_octet, ETHERTYPE_ARP, NULL, 0, l, 0) == -1 )
	{
	  fprintf(stderr, "Error building Ethernet header: %s\n",libnet_geterror(l));
      
      libnet_destroy(l);
	  exit(EXIT_FAILURE);
	}


	//WRITING PACKET

	bytesWritten = libnet_write(l);
  	
  	if ( bytesWritten != -1 )
  	{
  		printf("%d bytes written.\n", bytesWritten);
  	}
    
    else
    {
    	fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(l));
    }
    

    libnet_destroy(l);    
}