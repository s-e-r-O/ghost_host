#include <netinet/ip.h>
#include <netinet/in.h>

#include "recv.h"

/* RFC791 -> https://tools.ietf.org/html/rfc791 */

void ip_reader(const u_char *bytes, bpf_u_int32 total_len)
{
    struct ip *headerIP = (struct ip *) bytes;

    switch(headerIP->ip_p){
        case IPPROTO_ICMP:
            //icmp_reader(bytes + headerIP -> ip_hl * 4, total_len - (headerIP->ip_hl*4));
            break;
    }
}
