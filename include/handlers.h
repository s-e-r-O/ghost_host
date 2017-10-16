#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "conf-data.h"

#ifndef HANDLERS_H_

	#define HANDLERS_H_ 

	void pcap_callback(u_char *user, const struct  pcap_pkthdr *h, const u_char *bytes);
	int ether_handler(const u_char *bytes, bpf_u_int32 total_len, struct configuration *conf_data);

	int ip_handler(const u_char *bytes, struct configuration *conf_data);
	int icmp_handler(const u_char *bytes, u_int16_t total_len, struct configuration *conf_data);
	
	int arp_handler(const u_char *bytes, bpf_u_int32 total_len, struct configuration *conf_data);

#endif