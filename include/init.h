#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "conf-data.h"

#ifndef INIT_H_
	#define INIT_H_
	
	void ghost_host_libnet_init(struct configuration *c, const char* device);
	void ghost_host_pcap_init(pcap_t** p, const char* device);
	void ghost_host_data_init(struct configuration *c, libnet_t* l);
	void ghost_host_pcap_init_filter(pcap_t** p, const char* device);
#endif