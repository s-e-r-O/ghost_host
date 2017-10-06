#include <net/if_arp.h>

#include "recv.h"

/* RFC826 -> https://tools.ietf.org/html/rfc826 */

void arp_reader(const u_char *bytes, bpf_u_int32 data_len)
{
	struct arphdr *headerARP = (struct arphdr *) bytes;
	switch(ntohs(headerARP->ar_op)){
		case ARPOP_REQUEST:
			printf("Someone made an ARP request\n");
			break;
		case ARPOP_REPLY:
			printf("Someone made an ARP reply\n");
			break;
	}
}
