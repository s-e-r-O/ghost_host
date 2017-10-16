#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "handlers.h"

/* IEEE Standard for Ethernet -> http://standards.ieee.org/getieee802/download/802.3-2012_section1.pdf */
/* More info on libnet functions ->	https://github.com/sam-github/libnet/blob/master/libnet/include/libnet/libnet-functions.h */

int ether_handler(const u_char *bytes, bpf_u_int32 total_len, struct configuration *conf_data)
{
	
	struct ether_header *headerEthernet = (struct ether_header *) bytes;
	
	// 'send' will determinate if a package injection is needed
	int send = 0;

	static u_int16_t last_ethertype = 0x0000; // Initial value isn't ETHERTYPE_IP nor ETHERTYPE_ARP

	switch(ntohs(headerEthernet->ether_type)){
		case ETHERTYPE_IP:

			/* 
				We can't modify the injected packet if it was initizialized as an ARP package, 
				instead we have to clear it, and build it from the ground up,
			*/

			/* <<<<<WARNING - NOT THE PRETTIEST WAY TO DO THIS! */
			if (last_ethertype != ETHERTYPE_IP){
				libnet_clear_packet(conf_data->l);
				
				last_ethertype = ETHERTYPE_IP;
					
				*(conf_data->libnet_tags.ether_tag) = LIBNET_PTAG_INITIALIZER;
				*(conf_data->libnet_tags.arp_tag) = LIBNET_PTAG_INITIALIZER;
			}
			/* NOT THE PRETTIEST WAY TO DO THIS! - WARNING>>>>>> */
				
			// 'send' will be true if the package contains an ICMP echo request for our ghost IP address
			send = ip_handler(bytes + sizeof(*headerEthernet), conf_data);
			break;

		case ETHERTYPE_ARP:
			/* 
				We can't modify the injected packet if it was initizialized as an ICMP package, 
				instead we have to clear it, and build it from the ground up,
			*/
			
			/* <<<<<WARNING - NOT THE PRETTIEST WAY TO DO THIS! */
			if (last_ethertype != ETHERTYPE_ARP){
				libnet_clear_packet(conf_data->l);
				last_ethertype = ETHERTYPE_ARP;

				*(conf_data->libnet_tags.ether_tag) = LIBNET_PTAG_INITIALIZER;
				*(conf_data->libnet_tags.ip_tag) = LIBNET_PTAG_INITIALIZER;
				*(conf_data->libnet_tags.icmp_tag) = LIBNET_PTAG_INITIALIZER;
			}
			/* NOT THE PRETTIEST WAY TO DO THIS! - WARNING>>>>>> */

			// 'send' will be true if the package contains an ARP Request asking for our ghost IP address
			send = arp_handler(bytes + sizeof(*headerEthernet), total_len - sizeof(*headerEthernet), conf_data);
			break;
	}

	if (send){

		*(conf_data->libnet_tags.ether_tag) = 
					libnet_build_ethernet(	headerEthernet->ether_shost, 						// Destination MAC Address 
											conf_data->ghost_host.hrd_addr, 					// Source MAC Address
											ntohs(headerEthernet->ether_type), 					// Ethertype
											NULL, 0,											// Payload (not considered in this layer), Payload Length
											conf_data->l, *(conf_data->libnet_tags.ether_tag));	// libnet_t pointer, libnet tag of this specific Ethernet header
		
		/*
			Auto-build is a simpler way to achieve packet injection, but it uses the device's real MAC address, instead
			of the ghost one that we created. (Can be used for debugging in certain cases).

			Can't be altered with the use of libnet tags!!

			libnet_autobuild_ethernet(	headerEthernet->ether_shost, 
										ntohs(headerEthernet->ether_type), 
										conf_data->l);
		*/
	}

	return send;
	
}