# pcap_tcp_sniff
## C language Header File
```c
#include <stdlib.h>  //자료형이나 여러 기능이 있는 헤더파일
#include <stdio.h>  //기본 입출력 헤더파일
#include <pcap.h>  //패킷 분석시 이용할 헤더파일
#include <arpa/inet.h>  //숫자로 IP 주소를 조작하는 헤더파일
```
필요한 헤더파일들을 선언해 줍니다.

## 패킷 캡쳐에 필요한 header
```c
/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};
```

필요한 헤더들(Ethernet, IP, TCP)을 찾아 코드를 추가해줍니다.

## Main Code 해석
```c
int main()
{
  pcap_t *handle;    //패킷 캡처 핸들
  char *dev;    // 네트워크 디바이스 이름
  char errbuf[PCAP_ERRBUF_SIZE];    // 오류 메시지를 저장할 버퍼
  struct bpf_program fp;    // 필터 관련 구조체
  char filter_exp[] = "tcp";    // 필터 내용
  bpf_u_int32 net;    // 아이피 주소를 담을 변수
  
  dev = pcap_lookupdev(errbuf);    // 네트워크 디바이스 찾기
  if (dev == NULL){    // Null 값인지 확인하기
    printf("%s\n", errbuf);
    exit(1);
  }
  printf("DEV : %s\n", dev);    // 네트워크 디바이스 이름 출력

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);    // 패킷 캡처 핸들 열기
  if(handle == NULL){    // handle이 잘 생성 됬는지 검사
  	printf("Handle is Null");
  	exit(1);
  }

  pcap_compile(handle, &fp, filter_exp, 0, net);    // 필터 컴파일

  if (pcap_setfilter(handle, &fp) !=0) {    // 필터 적용
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);    //패킷 캡처 루프

  pcap_close(handle); // 핸들 닫기

  return 0;
}
```

위와 같은 코드로 네트워크 디바이스를 잡아주고 그 뒤 패킷 캡쳐 핸들을 열어 필터를 적용시키고 루프를 돌며 got_packet의 함수가 계속 실행되는 코드입니다.
