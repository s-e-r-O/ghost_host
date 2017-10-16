#include <pcap/pcap.h>
#include <libnet.h>

#ifndef CONF_DATA_H_
	#define CONF_DATA_H_

	struct configuration
	{
		struct 
		{
		    u_int32_t ip_addr; 		// IP address for the ghost host. 
		    u_int8_t* hrd_addr; 	// MAC address for the ghost host.
		} ghost_host;
		pcap_t *p;
		libnet_t *l;
		struct
		{
			libnet_ptag_t *ether_tag;
			libnet_ptag_t *ip_tag;
			libnet_ptag_t *icmp_tag;
			libnet_ptag_t *arp_tag;
		} libnet_tags;	
	};
#endif