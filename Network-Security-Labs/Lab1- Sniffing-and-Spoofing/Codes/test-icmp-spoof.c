#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
// #include <arpa/inet.h>
#include <netinet/ip.h>
// #include <netinet/ip_icmp.h>
// #include <pcap.h>

// icmp header
struct icmpheader
{
    // icmp message type
    unsigned char       icmp_type;
    // error code
    unsigned char       icmp_code;
    // checksum for icmp header and data
    unsigned short int  icmp_chksum;
    // used for identifying request
    unsigned short int  icmp_id;
    // sequence number
    unsigned short int  icmp_seq;
};

// ip header
struct ipheader
{
    // IP header length
    unsigned char       iph_length:4;
    // IP version
    unsigned char       iph_ver:4;
    // Type of service
    unsigned short int  iph_tos;
    // IP packet length(header + data)
    unsigned short int  iph_len;
    // Identification
    unsigned short int  iph_ident;
    // Fragmentation flags
    unsigned short int  iph_flag:3;
    // Flags offset
    unsigned short int  iph_offset:13;
    // time to live
    unsigned char       iph_ttl;
    // Protocol type
    unsigned char       iph_protocol;
    // IP datagram checksum
    unsigned short int  iph_chksum;
    // Source IP address
    struct in_addr      iph_sourceip;
    // Destination IP address
    struct in_addr      iph_destip;
};

// calculating checksum
unsigned short in_chksum(unsigned short *buf, int length)
{
    unsigned short *w=buf;
    int nleft=length;
    int sum=0;
    unsigned short temp=0;
    while(nleft>1)
    {
        sum+=*w++;
        nleft-=2;
    }
    if(nleft==1)
    {
        *(u_char *)(&temp)=*(u_char *)w;
        sum+=temp;
    }
    sum=(sum >> 16)+(sum & 0xffff);
    sum+=(sum >> 16);
    return (unsigned short)(~sum);
}
// sending raw IP
void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    int enable=1;

    // creating raw network packet
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // setting up socket option
    setsockopt(sock,IPPROTO_IP, IP_HDRINCL, &enable,sizeof(enable));

    // destination info
    dest_info.sin_family=AF_INET;
    dest_info.sin_addr=ip->iph_destip;
    // dest_info.sin_port = htons(9090);

    // sending raw packet
    sendto(sock,ip,htons(ip->iph_len),0,(struct sockaddr *)&dest_info, sizeof(dest_info));
    // printf("%u\t\t%u",ip->iph_sourceip, ip->iph_destip);
    
    // closing socket
    close(sock);
}

// main
int main()
{
    // buffer of packet
    char buffer[1500];
    memset(buffer,0,1500);
    struct ipheader *ip=(struct ipheader *)buffer;
    /**********************************************/
    /* filling icmp header                         /
    /**********************************************/
    struct icmpheader *icmp = (struct icmpheader *)(buffer+sizeof(struct ipheader));
    // type 8= request, 0=reply
    icmp->icmp_type=8;

    // calculating checksum 
    icmp->icmp_chksum=0;
    icmp->icmp_chksum=in_chksum((unsigned short *)icmp, sizeof(struct icmpheader));

    /**********************************************/
    /* filling ip header                           /
    /**********************************************/
    ip->iph_ver=4;
    ip->iph_length=5;
    ip->iph_ttl=64;
    ip->iph_sourceip.s_addr=inet_addr("10.0.2.4");
    ip->iph_destip.s_addr=inet_addr("10.0.2.5");
    ip->iph_protocol=IPPROTO_ICMP;
    ip->iph_len=ntohs(sizeof(struct ipheader)+sizeof(struct icmpheader));

    /**********************************************/
    /* sending raw packet                          /
    /**********************************************/
    // for(int i=0;i<10;i++)
    send_raw_ip_packet(ip);
    // show(ip);
    return 0;
}