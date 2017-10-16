#ifndef CONF_H_
#define CONF_H_
	#include <pcap/pcap.h>
	#include <libnet.h>

	struct configuration
	{
		struct 
		{
		    u_int32_t ip_addr; // IP address for the ghost host. It has to be in the same net as requesting hosts.
		    u_int8_t* hrd_addr; // MAC address for the ghost host.
		} ghost_host;
		pcap_t *p;
		libnet_t *l;	
	};
#endif