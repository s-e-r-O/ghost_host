#include <pcap/pcap.h>

void pcap_callback(u_char * user, const struct  pcap_pkthdr *h, const u_char *bytes);