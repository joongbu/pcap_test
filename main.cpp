#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


int main()

{



    pcap_t *handle;            /* Session handle */


    char *dev;            /* The device to sniff on */

    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */

   dev  =  pcap_lookupdev(errbuf);

    if (dev == NULL) {

        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

        return(2);

    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {

        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

        return(2);

    }

    pcap_loop(handle, -1, got_packet, NULL);


    /* And close the session */

    pcap_close(handle);

    return(0);

}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    libnet_ethernet_hdr *ethernet_header = (libnet_ethernet_hdr*) packet;

        printf("destination MAC : %s\n",ether_ntoa((ether_addr*)(ethernet_header->ether_dhost)));
        printf("source MAC : %s\n",ether_ntoa((ether_addr*)(ethernet_header->ether_shost)));
        if(ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
        {
            libnet_ipv4_hdr *ip_header = (libnet_ipv4_hdr *)(packet + sizeof(libnet_ethernet_hdr));
            printf("ip source : %s\n",inet_ntoa(ip_header->ip_src));
            printf("ip destination : %s\n",inet_ntoa(ip_header->ip_dst));

            if(ip_header->ip_p == IPPROTO_TCP) //0x06
            {
                libnet_tcp_hdr *tcp_header = (libnet_tcp_hdr *)(packet + sizeof(libnet_ethernet_hdr) + (ip_header->ip_hl*4));
                printf("tcp source port : %d\n", ntohs(tcp_header->th_sport));
                printf("tcp destination port : %d\n",ntohs(tcp_header->th_dport));

            }
            if(ip_header->ip_p == IPPROTO_UDP)//0x11
            {
                libnet_udp_hdr *udp_header = (libnet_udp_hdr *)(packet + sizeof(libnet_ethernet_hdr) + (ip_header->ip_hl*4));
                printf("udp source port : %d\n", ntohs(udp_header->uh_sport));
                printf("udp destination port : %d\n",ntohs(udp_header->uh_dport));
            }

        }
}
