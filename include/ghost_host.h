#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

struct g_host
{
    uint32_t ip_addr; // IP address for the ghost host. It has to be in the same net as requesting hosts.
    uint8_t mac_addr[ETH_ALEN]; // MAC address for the ghost host.
};