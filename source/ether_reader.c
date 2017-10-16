#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "recv.h"

/* IEEE Standard for Ethernet -> http://standards.ieee.org/getieee802/download/802.3-2012_section1.pdf */

void ether_reader(const u_char *bytes, bpf_u_int32 total_len, struct configuration *conf_data)
{
	
	struct ether_header *headerEthernet = (struct ether_header *) bytes;

	int send = 0;
	switch(ntohs(headerEthernet->ether_type)){
		case ETHERTYPE_IP:
			if (*headerEthernet->ether_dhost == *conf_data->ghost_host.hrd_addr){
				printf("Someone wants to contact with us :D\n");
				// Trying to find an ICMP package
				send = ip_reader(bytes + sizeof(*headerEthernet), total_len - sizeof(*headerEthernet), conf_data);
			}
			break;
		case ETHERTYPE_ARP:
			// Trying to reach a MAC Address
			send = arp_reader(bytes + sizeof(*headerEthernet), total_len - sizeof(*headerEthernet), conf_data);
			break;
	}

	if (send){
		extern libnet_ptag_t ether_tag;
		ether_tag = libnet_build_ethernet(headerEthernet->ether_shost, conf_data->ghost_host.hrd_addr, \
				ntohs(headerEthernet->ether_type), NULL, 0, conf_data->l, ether_tag);
		
		//int length = 6;
		//u_int8_t *mac_addr = libnet_hex_aton("B0:10:41:80:4C:D7", &length);
		//libnet_autobuild_ethernet(headerEthernet->ether_shost, ntohs(headerEthernet->ether_type), conf_data->l);
		int bytes_written = libnet_write(conf_data->l);
		if (bytes_written != -1){
			printf("%d bytes written\n", bytes_written);
		}
	}
	
}