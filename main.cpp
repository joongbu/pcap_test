
#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int ip_destination(const u_char *p, int a, int b);
int ip_source(const u_char *p, int a, int b);
void ethernet(const u_char *p, int a, int b);
int tcp_source(const u_char *p);
int tcp_destination(const u_char *p);
int udp_source(const u_char *p);
int udp_destination(const u_char *p);

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

    ethernet(p,0,11);
    if((int)p[12] == 8 && (int)p[13] == 0)
    {
        ip_source(p,26,29);
        ip_destination(p,30,33);
        if((int)p[23] == 6)
        {

           tcp_source(p);
           tcp_destination(p);
        }
       if((int)p[23] == 17)
       {

           udp_source(p);
           udp_destination(p);

       }
    }


}
void ethernet(const u_char *p, int a, int b)
{
    printf("ethernet destination :");
    for(a ; a<=b/2; a++)
    {
        printf("%02x",p[a]);
        if(a<b/2)
        printf(":");
    }
    printf("\n");
    printf("ethernet source :");
    for(a=b/2;a <=b;a++)
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
    return 0;
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
    return 0;
}

int tcp_destination(const u_char *p)
{   uint8_t buffer[2] = {p[36],p[37]};
    uint16_t s;
    ntohs(buffer[0]);
    ntohs(buffer[1]);
    s =buffer[0] + buffer[1];
    printf("tcp destination ip : %d\n",s);
    return 0;


}
int tcp_source(const u_char *p)
{
    uint8_t buffer[2]= {p[34],p[35]};
    uint16_t s;
    ntohs(buffer[0]);
    ntohs(buffer[1]);
    s =buffer[0] + buffer[1];
    printf("tcp source ip : %d\n",s);
    return 0;
}

int udp_destination(const u_char *p)
{
    uint8_t buffer[2] = {p[36],p[37]};
    uint16_t s;

    ntohs(buffer[0]);
    ntohs(buffer[1]);
    s =buffer[0] + buffer[1];
    printf("udp destination ip : %d\n",s);
    return 0;
                    }
int udp_source(const u_char *p)
{
    uint8_t buffer[2]= {p[34], p[35]};
    uint16_t s;
    ntohs(buffer[0]);
    ntohs(buffer[1]);
    s =buffer[0] + buffer[1];
    printf("udp source ip : %d\n",s);
    return 0;
                    }
