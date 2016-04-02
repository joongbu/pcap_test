#include <pcap.h>
#include <stdint.h>
#include <stdio.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int ip_destination(const u_char *p, int a, int b);
int ip_source(const u_char *p, int a, int b);
void ethernet_destination(const u_char *p, int a, int b);
void ethernet_source(const u_char *p, int a, int b);
uint8_t tcp_source(const u_char *p);
uint8_t tcp_destination(const u_char *p);
uint8_t udp_source(const u_char *p);
uint8_t udp_destination(const u_char *p);

int main()

{

    pcap_t *handle;            /* Session handle */

    char *dev;            /* The device to sniff on */

    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */

    struct bpf_program fp;        /* The compiled filter */

    char filter_exp[] = "port 23";    /* The filter expression */

    bpf_u_int32 mask;        /* Our netmask */

    bpf_u_int32 net;        /* Our IP */


    /* Define the device */

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {

        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

        return(2);

    }


    /* Find the properties for the device */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {

        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);

        net = 0;

        mask = 0;

    }

    /* Open the session in promiscuous mode */

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {

        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

        return(2);

    }

    /* Compile and apply the filter */

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {

        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));

        return(2);

    }


    pcap_loop(handle, -1, got_packet, NULL);


    /* And close the session */

    pcap_close(handle);

    return(0);

}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p) {

    ethernet_destination(p,0,5);
    ethernet_source(p,6,11);
    if((int)p[12] == 8 && (int)p[13] == 0)
    {
        ip_source(p,26,29);
        ip_destination(p,30,33);
        if((int) p[23] == 6);
        {
            uint8_t tcp_source_port =0, tcp_destination_port = 0;
            tcp_source_port = (uint8_t)tcp_source(p);
            tcp_destination_port = (uint8_t)tcp_destination(p);
            //destination so big????....
            printf("tcp source port(hex) : %x\ntcp destination(hex) : %x\n",tcp_source(p),tcp_destination(p));
            printf("tcp source port : %d\ntcp destination port : %d\n", tcp_source_port,tcp_destination_port);
        }
      if((int)p[23] == 11)
       {

           udp_source(p);
           udp_destination(p);


       }
    }


}
void ethernet_destination(const u_char *p, int a, int b)
{
    printf("ethernet destination :");

    for(a ; a<=b; a++)
    {
        printf("%02x",p[a]);
        if(a<b)
            printf(":");
    }
    printf("\n");
}
void ethernet_source(const u_char *p, int a, int b)
{
    printf("ethernet source :");

    for(a ; a<=b; a++)
    {
        printf("%02x",p[a]);
        if(a<b)
            printf(":");
    }
    printf("\n");
}
int ip_destination(const u_char *p, int a, int b)
{
    printf("ip destination : ");
    for(a; a<=b; a++)
    {
        printf("%02d",p[a]);
        if(a<b)
            printf(".");
    }
    printf("\n");
    return 1;
}

int ip_source(const u_char *p, int a, int b)
{
    printf("ip source : ");
    for(a; a<=b; a++)
    {
        printf("%02d",p[a]);
        if(a<b)
            printf(".");
    }
    printf("\n");
    return 1;
}

uint8_t tcp_destination(const u_char *p)
{   uint8_t buffer[2] = {p[36], p[37]};
    uint16_t s = NULL;

        s = buffer[0] << 8 | buffer[1];
    return s;


}
uint8_t tcp_source(const u_char *p)
{
    uint8_t buffer[2]= {p[34], p[35]};
    uint16_t s = NULL;
        s = buffer[0] << 8 | buffer[1];
    return s;
}

uint8_t udp_destination(const u_char *p)
{
    uint8_t buffer[2]= {p[36], p[37]};
    uint16_t s = NULL;
        s = buffer[0] << 8 | buffer[1];
    return s;
                    }
uint8_t udp_source(const u_char *p)
{
    uint8_t buffer[2]= {p[34], p[35]};
    uint16_t s = NULL;
        s = buffer[0] << 8 | buffer[1];
    return s;
                    }
