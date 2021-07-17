#include<stdio.h>
#include<sys/time.h>
#include<errno.h>
#include<signal.h>
#include<time.h>
#include<stdlib.h>
#include<unistd.h>
#include<netdb.h>
#include<string.h>
#include<strings.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in_systm.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/in_systm.h>
#define BUFSIZE 1500
struct rec{
	u_short rec_seq;
	u_short rec_ttl;
	struct timeval rec_tv;
};

char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

int datalen;
char *host;
u_short sport,dport;
int nsent;
pid_t pid;
int probe,nprobes;
int sendfd,recvfd;
int ttl,max_ttl;
int verbose;

struct proto{
	const char*(*icmpcode)(int);
	int (*recv)(int,struct timeval*);
	struct sockaddr *sasend;    //dest addr, the destination
	struct sockaddr *sarecv;    //recv addr, store who send the message
	struct sockaddr *salast;
	struct sockaddr *sabind;    //bind the source port
	socklen_t salen;
	int icmpproto;
	int ttllevel;
	int ttloptname;
}*pr;
int gotalarm;
const char *icmpcode_v4(int code){
	static char errbuf[100];
	switch(code){
		case 0:return("network unreachable");
		case 1:return("host unreachable");
		case 2:return("protocol unreachable");
		case 3:return("port unreachable");
		case 4:return("fragmentation required but DF bit set");
		case 5:return("source route failed");
		case 6:return("destination network unknown");
		case 7:return("destination host unknown");
		case 8:return("source host isolated(obsolete)");
		case 9:return("destination network administartively prohibited");
		case 10:return("destination host administartively prohibited");
		case 11:return("network unreachable for TOS");
		case 12:return("host unreachable for TOS");
		case 13:return("communication error");
		case 14:return("host recedenc violation");
		case 15:return("precedence cutoff in effect");
		default:sprintf(errbuf,"unknown code %d",code);
	}
	return errbuf;
}
void sig_alrm(int signo){
	gotalarm=1;
	return;
}
void tv_sub(struct timeval *out,struct timeval *in){
	if((out->tv_usec-=in->tv_usec)<0){
		--out->tv_sec;
		out->tv_sec+=1000000;
	}
	out->tv_sec-=in->tv_sec;
}
void traceloop(void){
	int seq,code,done;
	double rtt;
	struct rec *rec;
	struct timeval tvrecv;
	if((recvfd=socket(pr->sasend->sa_family,SOCK_RAW,pr->icmpproto))<0){
		printf("recvfd:socket failed\n");
		return;
	}
	setuid(getuid());
	if((sendfd=socket(pr->sasend->sa_family,SOCK_DGRAM,0))<0){
		printf("sendfd:socket failed\n");
		return;
	}

	pr->sabind->sa_family=pr->sasend->sa_family;
	sport=(getpid()&0xffff) | 0x8000;
	((struct sockaddr_in*)pr->sabind)->sin_port=htons(sport);

	if(bind(sendfd,pr->sabind,pr->salen)<0){
		printf("bind error\n");
		return;
	}

	sig_alrm(SIGALRM);
	seq=0;
	done=0;
	for(ttl=1;ttl<=max_ttl&&done==0;ttl++){
		setsockopt(sendfd,pr->ttllevel,pr->ttloptname,&ttl,sizeof(int));//modify ttl
		bzero(pr->salast,pr->salen);
		printf("%2d ",ttl);
		fflush(stdout);
		for(probe=0;probe<nprobes;probe++){
			/*
			 *             *these sendbuf is just
			 *                         *used to exam if the received data is sended by our program
			 *                                     */
			rec=(struct rec*)sendbuf;
			rec->rec_seq=++seq;
			rec->rec_ttl=ttl;

			gettimeofday(&rec->rec_tv,NULL);
			((struct sockaddr_in*)pr->sasend)->sin_port=htons(dport+seq);
			if(sendto(sendfd,sendbuf,datalen,0,pr->sasend,pr->salen)<0){//send to dest with ttl added
				perror("bad sendto");
				continue;
			}

			//if time_out print * else print info
			if((code=(*pr->recv)(seq,&tvrecv))==-3){
				printf(" *");
			}else{
				char str[NI_MAXHOST];
				if(memcmp(pr->sarecv,pr->salast,pr->salen)!=0){
					if(getnameinfo(pr->sarecv,pr->salen,str,sizeof(str),NULL,0,0)==0){
						printf(" %s (%s)",str,inet_ntoa(((struct sockaddr_in*)pr->sarecv)->sin_addr));
					}else{
						printf(" %s",inet_ntoa(((struct sockaddr_in*)pr->sarecv)->sin_addr));
					}
					memcpy(pr->salast,pr->sarecv,pr->salen);
				}
				tv_sub(&tvrecv,&rec->rec_tv);
				rtt=tvrecv.tv_sec*1000.0+tvrecv.tv_usec/1000;
				printf("  %.3f ms",rtt);

				if(code==-1){   //reach the dest
					done++;
				}else if(code>0){
					printf(" (ICMP %s)",(*pr->icmpcode)(code));
				}
			}
			fflush(stdout);
		}
		printf("\n");
	}
}
int recv_v4(int seq,struct timeval *tv){
	int hlen1,hlen2,icmplen,ret;
	socklen_t len;
	ssize_t n;
	struct ip *ip,*hip;
	struct icmp *icmp;
	struct udphdr *udp;

	gotalarm=0;
	for(;;){
		if(gotalarm){
			return -3;
		}
		len=pr->salen;
		alarm(3);
		n=recvfrom(recvfd,recvbuf,sizeof(recvbuf),0,pr->sarecv,&len);//data len
		if(n<0){
			if(errno==EINTR){
				continue;
			}else{
				printf("recvfrom error\n");
				return 0;
			}
		}else{
			//if recvfrom ok , close the alarm
			alarm(0);
		}

		//read data
		ip=(struct ip*)recvbuf;
		hlen1=ip->ip_hl<<2;//ip len
		icmp=(struct icmp*)(recvbuf+hlen1);
		if((icmplen=n-hlen1)<8){
			continue;
		}
		if(icmp->icmp_type==ICMP_TIMXCEED&&
				icmp->icmp_code==ICMP_TIMXCEED_INTRANS){
			if(icmplen<8+sizeof(struct ip)){
				continue;
			}
			//get icmp data
			hip=(struct ip*)(recvbuf+hlen1+8);
			hlen2=hip->ip_hl<<2;
			if(icmplen<8+hlen2+4){
				continue;
			}
			udp=(struct udphdr *)(recvbuf+hlen1+8+hlen2);
			if(hip->ip_p==IPPROTO_UDP&&
					udp->source==htons(sport)&&
					udp->dest==htons(dport+seq)){
				ret=-2;
				break;
			}
		}else if(icmp->icmp_type==ICMP_UNREACH){
			if(icmplen<8+sizeof(struct ip))
				continue;
			hip=(struct ip*)(recvbuf+hlen1+8);
			hlen2=hip->ip_hl<<2;
			if(icmplen<8+hlen2+4)
				continue;
			udp=(struct udphdr*)(recvbuf+hlen1+8+hlen2);
			if(hip->ip_p==IPPROTO_UDP&&
					udp->source==htons(sport)&&
					udp->dest==htons(dport+seq)){
				if(icmp->icmp_code==ICMP_UNREACH_PORT)
					ret=-1;     //reach the destination
				else
					ret=icmp->icmp_code;
				break;
			}
		}
	}
	gettimeofday(tv,NULL);
	return ret;
}

struct proto proto_v4={icmpcode_v4,recv_v4,NULL,NULL,NULL,NULL,0,IPPROTO_ICMP,IPPROTO_IP,IP_TTL};

int datalen=sizeof(struct rec);
int max_ttl=30;
int nprobes=3;
u_short dport=32768+666;//hope the port of dest is not used

struct addrinfo *host_serv(const char *host,const char *serv,int family,int socktype){
	int n;
	struct addrinfo hints,*res;
	bzero(&hints,sizeof(hints));
	hints.ai_flags=AI_CANONNAME;
	hints.ai_family=family;
	hints.ai_socktype=socktype;
	if((n=getaddrinfo(host,serv,&hints,&res))!=0){
		return NULL;
	}
	return (res);
}
int main(int argc,char *argv[]){
	int c;
	struct addrinfo *ai;
	struct sigaction s_action;
	char h[20]={0};
	while((c=getopt(argc,argv,"m:v"))!=-1){
		switch(c){
			case 'm':
				if((max_ttl=atoi(optarg))<0){
					printf("invalid input\n");
				}
				break;
			case 'v':
				verbose++;
				break;
			case '?':
				printf("unrecognized\n");
				return -1;
		}
	}
	if(optind!=argc-1){
		printf("error input\n");
		return -1;
	}
	host=argv[optind];

	pid=getpid();

	bzero(&s_action,sizeof(s_action));
	s_action.sa_handler=sig_alrm;
	s_action.sa_flags=SA_INTERRUPT;
	sigaction(SIGALRM,&s_action,NULL);

//	signal(SIGALRM,sig_alrm);
	ai=host_serv(host,NULL,0,0);
	inet_ntop(AF_INET,&((struct sockaddr_in*)(ai->ai_addr))->sin_addr,h,sizeof(h));
	printf("traceroute to %s (%s): %d hops max, %d data bytes\n",
			ai->ai_canonname?ai->ai_canonname:h,h,max_ttl,datalen);

	if(ai->ai_family==AF_INET){
		pr=&proto_v4;
	}else{
		printf("UNKNOW address family\n");
		return -1;
	}

	pr->sasend=ai->ai_addr;
	pr->sarecv=(struct sockaddr*)calloc(1,ai->ai_addrlen);
	pr->salast=(struct sockaddr*)calloc(1,ai->ai_addrlen);
	pr->sabind=(struct sockaddr*)calloc(1,ai->ai_addrlen);
	pr->salen=ai->ai_addrlen;
	traceloop();
	exit(0);
}