#include <netinet/ip_icmp.h>

#include "recv.h"

/* RFC792 -> https://tools.ietf.org/html/rfc792 */

/* Different messages depending of Type property of the ICMP Header */
void prepare_msg_array(char* type_msg[]);

void icmp_reader(const u_char *bytes, bpf_u_int32 total_len)
{

  printf("ICMP Package:\n");

	struct icmphdr *headerICMP = (struct icmphdr *) bytes;
	
  u_int8_t type = ntohs(headerICMP->type);

  char *type_msg[NR_ICMP_TYPES];

  prepare_msg_array(type_msg);

  printf("Type: %u (%s)\n", type, type_msg[type]);
  printf("Total Data Length: %u\n", total_len);
  printf("Data Length: %u\n", total_len - sizeof(*headerICMP));

}	

/* Different messages depending of Type property of the ICMP Header */
void prepare_msg_array(char* type_msg[])
{
  type_msg[ICMP_ECHOREPLY] = "Echo Reply";
  type_msg[ICMP_DEST_UNREACH] = "Destination Unreachable";
  type_msg[ICMP_SOURCE_QUENCH] = "Source Quench";
  type_msg[ICMP_REDIRECT] = "Redirect (change route)";
  type_msg[ICMP_ECHO] = "Echo Request";
  type_msg[ICMP_TIME_EXCEEDED] = "Time Exceeded";
  type_msg[ICMP_PARAMETERPROB] = "Parameter Problem";
  type_msg[ICMP_TIMESTAMP] = "Timestamp Request";
  type_msg[ICMP_TIMESTAMPREPLY] = "Timestamp Reply";
  type_msg[ICMP_INFO_REQUEST] = "Information Request";
  type_msg[ICMP_INFO_REPLY] = "Information Reply";
} 