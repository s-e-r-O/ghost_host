#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "recv.h"
#include "conf-data.h"
/* RFC826 -> https://tools.ietf.org/html/rfc826 */

int arp_reader(const u_char *bytes, bpf_u_int32 total_len, struct configuration *conf_data)
{
	int send = 0;

	struct arphdr *headerARP = (struct arphdr *) bytes;

	struct arppld
	{
		uint8_t ar_sha[headerARP->ar_hln];
		uint8_t ar_sip[headerARP->ar_pln];
		uint8_t ar_tha[headerARP->ar_hln];
		uint8_t ar_tip[headerARP->ar_pln];
	};
	
	struct arppld *payloadARP = (struct arppld *) (bytes + sizeof (*headerARP));

	if (ntohs(headerARP->ar_op) == ARPOP_REQUEST){
		/*printf("Who has %s? ", inet_ntoa(*(struct in_addr*) payloadARP->ar_tip));
		printf("Tell %s\n", inet_ntoa(*(struct in_addr*) payloadARP->ar_sip));*/

		if (*(uint32_t *)payloadARP->ar_tip == conf_data->ghost_host.ip_addr) {
			// Someone is asking for our ghost host
			printf("Someone is asking for our ghost host\n");
			extern libnet_ptag_t arp_tag;
			arp_tag = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, headerARP->ar_hln, headerARP->ar_pln \
						, ARPOP_REPLY, conf_data->ghost_host.hrd_addr, \
						(u_int8_t *) &conf_data->ghost_host.ip_addr, \
						payloadARP->ar_sha, payloadARP->ar_sip, NULL, 0, conf_data->l, arp_tag);
			
			//libnet_autobuild_arp(ARPOP_REPLY, conf_data->ghost_host.hrd_addr, (u_int8_t *) &conf_data->ghost_host.ip_addr, \
			//			payloadARP->ar_sha, payloadARP->ar_sip, conf_data->l);
			
			send = 1;
		}
	}
	return send;
}