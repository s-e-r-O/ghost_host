#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "headerReader.h"

void buildICMP(libnet_t *l, uint8_t *macDest, bpf_u_int32 totalLength, uint32_t ipDest, uint32_t ipSource)
{
	u_int16_t id;
	u_int16_t seq;
	char *ghostMAC = "aa:bb:cc:dd:ee:ff";
	struct ether_addr *MAC = ether_aton(ghostMAC);

	int bytesWritten;


/*
	char errBuf[LIBNET_ERRBUF_SIZE];
	libnet_t *l2;

	char *device = "enp0s8";
	
	l = libnet_init(LIBNET_LINK, "enp0s8", errBuf);

	if (l2 == NULL)
	{
		printf("Error. %s\n", errBuf);

		exit(1);
	}
	else
	{
		const char *device2;
		device2 = libnet_getdevice(l2);
		printf("Dispositivo: %s\n", device2);

		//EMPEZAMOS A CAPTURAR EL ARP:
		getPackets(l);
	}
*/	


	// GENERAMOS UN ID RANDOM 
	libnet_seed_prand (l);
	id = (u_int16_t)libnet_get_prand(LIBNET_PR16);



	// BUILDING ICMP 

	seq = 1;

	if (libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq, NULL, 0, l, 0) == -1)
	{
		fprintf(stderr, "Error building ICMP header: %s\n", libnet_geterror(l));

		libnet_destroy(l);
	    exit(EXIT_FAILURE);
	}


	// BUILDING IP

	if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H/* + (uint16_t *)(&totalLength)*/, 0, id, 0, 30, IPPROTO_ICMP, 0, ipSource, ipDest, NULL, 0, l, 0) == -1 )
	{
		fprintf(stderr, "Error building IP header: %s\n", libnet_geterror(l));
	    
	    libnet_destroy(l);
	    exit(EXIT_FAILURE);
	}



	//BULDING ETHERNET:

  	if (libnet_build_ethernet (macDest, MAC->ether_addr_octet, ETHERTYPE_IP, NULL, 0, l, 0) == -1 )
	{
	  fprintf(stderr, "Error building Ethernet header: %s\n",libnet_geterror(l));
      
      libnet_destroy(l);
	  exit(EXIT_FAILURE);
	}



	//WRITING PACKET:

	bytesWritten = libnet_write(l);
	
	if ( bytesWritten != -1 )
	{
		printf("%d bytes written.\n", bytesWritten);
	}

	else
	{
		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
	}

	libnet_destroy(l);
}