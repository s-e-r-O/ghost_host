#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <libnet.h>

#include "headerReader.h"

libnet_t *l;

void pcap_callback(u_char * user, const struct pcap_pkthdr *h, const u_char *bytes);

void  getPackets(libnet_t *lib)
{
	char errbuf[PCAP_ERRBUF_SIZE];
    char *device = "enp0s8"; 
    l = lib;

    /*pcap_lookupdev(errbuf);

    printf("Looking up for devices...\n");

    if(device == NULL)
    {
      printf("ERROR. No se pudo encontrar un dispositivo. %s\n", errbuf);
      exit(1);
    }
    */
    printf("Opening %s...\n", device);

    pcap_t* p = pcap_open_live(device, BUFSIZ, 1, 5000, errbuf);   //EL BUFSIZ ES EL NUMERO MAX DE BYTES QUE QUEREMOS CAPTURAR
 
    if (p == NULL) 
    {
      perror(errbuf);
      exit(-1);
    }

    printf("Starting to capture...\n");
      
    pcap_loop(p, -1, pcap_callback, NULL);   //devuelve 0 si ha leido el numero de paquetes especificado en el segundo parametro y un numero neg si hubo error
  
    exit(0);
}

void pcap_callback(u_char * user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    if ((h->caplen) == (h->len))
    {
    	getEthernet(bytes, h->len, l);
    }     
}



