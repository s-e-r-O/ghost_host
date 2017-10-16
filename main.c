#include <stdio.h>
#include <stdlib.h>

#include "conf-values.h"
#include "conf-data.h"

#include "init.h"
#include "handlers.h"

/* Global variables (:'v) to avoid rebuilding packets every time */

libnet_ptag_t ether_tag;
libnet_ptag_t ip_tag;
libnet_ptag_t arp_tag;
libnet_ptag_t icmp_tag;

int main(int nargs, char* args[])
{
    /* 
        Configuration data contains:
            - Ghost Host's IP and MAC address
            - Pointer to pcap_t struct
            - Pointer to libnet_t struct
        Used as an argument for pcap_callback 
    */
    struct configuration conf_data; 

    /* CONF_DEVICE is a constant defined in conf-values.h */
    const char *device = CONF_DEVICE;

    /* Initialization of libnet */
    ghost_host_libnet_init(&conf_data.l, device);

    /* Initialization of libpcap */
    ghost_host_pcap_init(&conf_data.p, device);

    /* Initialization of ghost host data */
    ghost_host_data_init(&conf_data, conf_data.l);

    /* Initialization of pcap filtering */
    ghost_host_pcap_init_filter(&conf_data.p, device);
    
    /* 
        Proccessing caputred packets by conf_data.p (until an ending condition occurs) on the pcap_callback
        routine and sending configuration data to it.
    */
    printf("Listening...\n");
    pcap_loop(conf_data.p, -1, pcap_callback, (u_char*) &conf_data);
    
    libnet_destroy(conf_data.l);

    exit(EXIT_SUCCESS);
}
