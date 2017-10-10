#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "recv.h"

/* IEEE Standard for Ethernet -> http://standards.ieee.org/getieee802/download/802.3-2012_section1.pdf */

void ether_reader(const u_char *bytes, bpf_u_int32 total_len)
{
	struct ether_header *headerEthernet = (struct ether_header *) bytes;

	switch(ntohs(headerEthernet->ether_type)){
		case ETHERTYPE_IP:
			// Trying to find an ICMP package
			ip_reader(bytes + sizeof(*headerEthernet), total_len - sizeof(*headerEthernet));
			break;
		case ETHERTYPE_ARP:
			// Trying to reach a MAC Address
			arp_reader(bytes + sizeof(*headerEthernet), total_len - sizeof(*headerEthernet));
			break;
	  }
}
