#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <libnet.h>

#include "conf-data.h"
#include "conf-values.h"
#include "recv.h"

int main(int nargs, char* args[])
{
    struct configuration conf_data; 
#if 0
    if (nargs > 1) {
        /*
            TO-DO: Turn 'char* args[1]' into a uint32_t (check existence of a function for that in net libs),
            for now, 169.254.30.10 will be hardcoded :(                   
        */
        ghost_host.ip_addr = 0xA9FE1E0A; //169.254.30.10
	    printf("Ghost Host IP Address: %s\n", args[1]);
    } else {
        char host_ip_addr_str[16];
	    printf("Ghost Host IP Address: ");
        scanf("%s", host_ip_addr_str);
        /*
            TO-DO: Turn 'char* host_ip_addr_str' into a uint32_t (check existence of a function for that in net libs),
            for now, 169.254.30.10 will be hardcoded :(                   
        */
        ghost_host.ip_addr = 0xA9FE1E0A;
    }
#endif
    /* errbuf is a char buffer used by libpcap to store error messages */
    char errbuf[LIBNET_ERRBUF_SIZE];
    
    const char *device = CONF_DEVICE;

    printf("Initializing libnet with device: %s\n", device);
    conf_data.l = libnet_init(LIBNET_LINK, device, errbuf);

    if (conf_data.l == NULL){
        printf("libnet_init() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Creating GHOST HOST data\n");
    int hrd_addr_length = 6;
    conf_data.ghost_host.ip_addr = libnet_name2addr4(conf_data.l, GHOST_IP_ADDR, LIBNET_DONT_RESOLVE);
    conf_data.ghost_host.hrd_addr = libnet_hex_aton(GHOST_HRD_ADDR, &hrd_addr_length);

    /* 
        Opening network device with BUFSIZ as the snapshot length, in promiscuous mode
        and with a timeout of 5000 ms
    */

    printf("Opening %s...\n", device);

    printf("Initializing libpcap...\n");
    conf_data.p = pcap_open_live(device, BUFSIZ, 1, 5000, errbuf);

    if (conf_data.p == NULL){
        perror(errbuf);
        exit(-1);
    }

    printf("Starting to capture...\n");
    /* 
        Proccessing packets of p until an ending condition occurs, with the routine pcap_callback 
        and sending ghost_host data to it.
    */
    pcap_loop(conf_data.p, -1, pcap_callback, (u_char*) &conf_data);
    exit(0);
}