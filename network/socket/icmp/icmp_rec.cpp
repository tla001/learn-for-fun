#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* IP首部长度 */
#define IP_HEADER_LEN sizeof(struct ip)
/* icmp报文长度 */
#define ICMP_PACKET_LEN sizeof(struct icmp)
/* IP + ICMP长度 */
#define IP_ICMP_PACKET_LEN IP_HEADER_LEN + ICMP_PACKET_LEN

void err_exit(const char *err_msg)
{
	perror(err_msg);
	exit(1);
}

/* 计算发送时间与接收时间的毫秒差 */
float time_interval(struct timeval *recv_time, struct timeval *send_time)
{
	float msec = 0;

	/* 如果接收的时间微妙小于发送的微妙 */
	if (recv_time->tv_usec < send_time->tv_usec)
	{
		recv_time->tv_sec -= 1;
		recv_time->tv_usec += 1000000;
	}
	msec = (recv_time->tv_sec - send_time->tv_sec) * 1000.0 + (recv_time->tv_usec - send_time->tv_usec) / 1000.0;

	return msec;
}

int main(void)
{
	struct ip *ip_header;
	struct icmp *icmp_packet;
	char buf[IP_ICMP_PACKET_LEN];
	struct timeval *recv_timeval, *send_timeval;
	int sockfd, ret_len;

	if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
		err_exit("sockfd()");

	recv_timeval = malloc(sizeof(struct timeval));
	while (1)
	{
		ret_len = recv(sockfd, buf, IP_ICMP_PACKET_LEN, 0);
		if (ret_len > 0)
		{
			/* 接收时间 */
			gettimeofday(recv_timeval, NULL);
			/* 取出ip首部 */
			/* 取出icmp报文 */
			ip_header = (struct ip *)buf;
			icmp_packet = (struct icmp *)(buf + IP_HEADER_LEN);
			/* 取出发送时间 */
			send_timeval = (struct timeval *)icmp_packet->icmp_data;
			printf("===============================\n");
			printf("from ip:%s\n", inet_ntoa(ip_header->ip_src));
			printf("icmp_type:%d\n", icmp_packet->icmp_type);
			printf("icmp_code:%d\n", icmp_packet->icmp_code);
			printf("time interval:%.3fms\n", time_interval(recv_timeval, send_timeval));
		}
	}

	free(recv_timeval);
	close(sockfd);
	return 0;
}