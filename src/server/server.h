#include <thread>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define IP_REQUEST 100  // IP request
#define IP_RESPONSE 101 // IP response
#define NET_REQUEST 102  // Network request
#define NET_RESPONSE 103  // Network response
#define KEEPALIVE 104     // Keepalive
#define SERVER_PORT   4321

#define MAX_EPOLL_EVENT 100
#define MAX_USER_NUM 20

#define MAX_DATA_LEN  4096

#define HEADER_SIZE 5
#define DATA_SIZE(msg) (msg.length - HEADER_SIZE)
#define IP_TO_UINT(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define IP_POOL_START IP_TO_UINT(13, 8, 0, 2)

struct Msg {
    int length;
    char type;
    char data[MAX_DATA_LEN];
};


struct UserInfo {
    int fd;
    int count;
    int secs;
    struct in_addr v4addr;
    struct in6_addr v6addr;
} user_info_table[MAX_USER_NUM];
