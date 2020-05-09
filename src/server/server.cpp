#include "server.h"
#include "logger.h"

int epfd;
int tunfd = -1;
int listenfd = -1; //for server to listen
// in_addr tun_addr;
Logger logger;
pthread_mutex_t mutex;
pthread_mutex_t sock_lock;

void setnonblocking(int sock) {
    int opts;
    opts = fcntl(sock, F_GETFL);
    if(opts < 0) {
        logger.error("fcntl(sock,GETFL)");
        exit(1);
    }
    opts = opts | O_NONBLOCK;
    if( fcntl(sock, F_SETFL, opts) < 0 ){
        logger.error("fcntl(sock,SETFL,opts)");
        exit(1);
    }
}

int find_user_by_fd(int fd) {
    if (fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < MAX_USER; ++i) {
        if (user_info_table[i].fd == fd) {
            pthread_mutex_unlock(&mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1;
}

int find_user_by_ip(uint32_t addr) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < MAX_USER; ++i) {
        if ((user_info_table[i].fd != -1) && (user_info_table[i].v4addr.s_addr == addr)) {
            pthread_mutex_unlock(&mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1;
}

//response to IP_REQUEST packet
int ip_response(int fd, int user) {
    logger.info("Send IP_RESPONSE packet to %d", fd);
    Msg msg;
    msg.type = IP_RESPONSE;
    char ip_str[16];
    inet_ntop(AF_INET, &(user_info_table[user].v4addr), ip_str, 16);

    sprintf(msg.data ,"%s 0.0.0.0 202.38.120.242 8.8.8.8 202.106.0.20", ip_str);

    msg.length = strlen(msg.data) + MSG_HEADER_SIZE + 1;
    int ret;
    pthread_mutex_lock(&sock_lock);
    ret = send(fd, &msg, msg.length, 0);
    pthread_mutex_unlock(&sock_lock);
    return ret;
}

int send_keepalive(int fd) {
    logger.info("Send KEEPALIVE packet to %d", fd);
    Msg msg;
    msg.type = KEEPALIVE;
    msg.length = MSG_HEADER_SIZE;
    int ret;
    pthread_mutex_lock(&sock_lock);
    ret = send(fd, &msg, msg.length, 0);
    pthread_mutex_unlock(&sock_lock);
    return ret;
}

int sock_receive(int fd, char* buff, int n) {
    int left = n;
    pthread_mutex_lock(&sock_lock);
    while (left > 0) {
        ssize_t recvn = recv(fd, buff + n - left, left, 0);
        if (recvn == -1) {
            return -1;
            // usleep(100);
            // continue;
        } 
        else if (recvn == 0) {
            return 0;
        } 
        else if (recvn > 0) {
            left -= recvn;
        } 
        else {
            logger.error("sock_receive error");
            return -1;
        }
    }
    pthread_mutex_unlock(&sock_lock);
    return n;
}

void recv_from_tun() {
    struct Msg msg;
    int ret = read(tunfd, msg.data, 1500);
    if (ret <= 0) {
        logger.error("Read packet to tun failed");
        return;
    }

    ret += MSG_HEADER_SIZE;
    struct iphdr *ip_head = (struct iphdr *)msg.data;
    char saddr[16], daddr[16];
    inet_ntop(AF_INET, &ip_head->saddr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &ip_head->daddr, daddr, sizeof(daddr));
    
    int user = find_user_by_ip(ip_head->daddr);
    if (user < 0) {
        logger.error("Cannot find client %s", daddr);
        return;
    }

    assert(user_info_table[user].fd != -1);
    assert(user_info_table[user].v4addr.s_addr == ip_head->daddr);

    int fd = user_info_table[user].fd;
    // printf("A packet from %s to %s\n", saddr, daddr);

    //send the packet back to client
    if (ip_head->version == 4) {
        msg.type = NET_RESPONSE;
        msg.length = ret;
        pthread_mutex_lock(&sock_lock);
        if((send(fd, &msg, msg.length, 0)) < 0) {
            pthread_mutex_unlock(&sock_lock);
            logger.error("Send to client %s failed", daddr);
            return;
        }
        pthread_mutex_unlock(&sock_lock);
        // printf("Send back NET_REPONSE packet, len=%d\n", ret);
    }
}

int process_packet_from_client(int fd, int user) {
    if (fd < 0) {
        return -1;
    }

    struct Msg msg;
    int n = sock_receive(fd, (char*)&msg, MSG_HEADER_SIZE);
    if (n <= 0){
        logger.error("Receive from client %d failed", fd);
        close(fd);
        for (int i = 0; i < MAX_USER; ++i) {
            if (user_info_table[i].fd == fd) {
                user_info_table[i].fd = -1;
            }
        }
        return -1;
    }

    if (msg.type == KEEPALIVE) {
        logger.info("Receive a keepalive packet from client %d", fd);
        user_info_table[user].secs = time(NULL);
    } 
    else if (msg.type == IP_REQUEST) {
        logger.info("Receive a IP REQUEST packet from client %d", fd);
        int ret;
        if ((ret=ip_response(fd, user) < 0)) {
            logger.info("Send ip response to %d failed", fd);
            // exit(0);
            return -1;
        }
        return ret;
    } 
    else if (msg.type == NET_REQUEST) {
        // printf("Receive a NET REQUEST packet\n");
        n = sock_receive(fd, msg.data,msg.length - MSG_HEADER_SIZE);
        if (n == msg.length - MSG_HEADER_SIZE) {
            iphdr *hdr = (struct iphdr *)msg.data;
            write(tunfd, msg.data, MSG_DATA_SIZE(msg));
        }
    } 
    else {
        logger.info("Receive unknown type packet from client %d", fd);
    }
    return 0;
}

struct epoll_event ev, events[20];

void event_add(int fd) {
    ev.data.fd = fd;
    ev.events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd,&ev);
}

void event_del(int fd) {
    ev.data.fd= fd;
    ev.events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
}

int init_server() {
    listenfd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (listenfd == -1) {
        logger.error("Server listening init failed");
        exit(-1);
    }
    struct sockaddr_in6 server_addr;
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(SERVER_PORT);
    int ret = bind(listenfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (ret == -1) {
        logger.error("Server bind failed");
        close(listenfd);
        exit(-1);
    }
    if ((ret = listen(listenfd, MAX_USER)) < 0) {
        logger.error("Server listen failed");
    }
    setnonblocking(listenfd);
    event_add(listenfd);
    return listenfd;
}

void init_iptable() {
    system("iptables -F");
    system("iptables -t nat -F");
    //accept to forward all packages
    system("iptables -A FORWARD -j ACCEPT");
    //when leave the interface, replace the source address
    system("iptables -t nat -A POSTROUTING -s 13.8.0.0/8 -j MASQUERADE");
}

//refer to linux kernel
int tun_alloc(char* dev_name) {
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0){
        logger.error("Create tun failed");
        return fd;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags |= IFF_TUN | IFF_NO_PI;

    if (*dev_name)
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        logger.error("Set tun device name failed");
        close(fd);
        return err;
    }

    char buffer[256];
    sprintf(buffer,"ip link set dev %s up", ifr.ifr_name);
    system(buffer);
    sprintf(buffer,"ip a add 13.8.0.1/24 dev %s", ifr.ifr_name);
    system(buffer);
    sprintf(buffer,"ip link set dev %s mtu %u", ifr.ifr_name, 1500);
    system(buffer);
    return fd;
}

void init_tun() {
    char dev[IFNAMSIZ];
    strcpy(dev, "4over6");
    tunfd = tun_alloc(dev);
    setnonblocking(tunfd);
    event_add(tunfd);
}

void* keepalive_func(void*) {
    pthread_mutex_lock(&mutex);
    while (true) {
        pthread_mutex_unlock(&mutex);
        sleep(1);
        pthread_mutex_lock(&mutex);
        for (int i = 0; i < MAX_USER; ++i) {
            int fd = user_info_table[i].fd;
            if (fd == -1) {
                continue;
            }
            if (time(NULL) - user_info_table[i].secs > 60) {
                logger.info("Timeout, remove client %d", fd);
                user_info_table[i].fd = -1;
                close(fd);
                event_del(fd);
            } else {
                user_info_table[i].count -= 1;
                if ( user_info_table[i].count == 0 ) {
                    send_keepalive(fd);
                    user_info_table[i].count = 20;
                }
            }
        }
    }
}
 
void close_all() {
    close(tunfd);
    close(listenfd);
    for (int i = 0; i < MAX_USER; ++i) {
        if (user_info_table[i].fd >= 0) {
            close(user_info_table[i].fd);
        }
    }
}

static void exit_handler(int sig) {
    close_all();
    logger.info("Exit");
    exit(0);
}

int main(){
    // When CTRL+C, close tunfd, listenfd, and fd for all users
    signal(SIGINT, exit_handler);

    epfd = epoll_create(MAX_EPOLL_EVENT);

    init_server();
    init_iptable();
    init_tun();

    logger.info("Server Start, Listening at %d", SERVER_PORT);
    logger.info("Listen fd: %d", listenfd);
    logger.info("Tun fd: %d", tunfd);

    int nfds, clientfd, ret;

    pthread_t keepalive_thread;
    ret = pthread_create(&keepalive_thread, NULL, keepalive_func, NULL);
    logger.info("Keep alive thread start");

    //init user_info_table
    for (int i = 0; i < MAX_USER; ++i) {
        user_info_table[i].v4addr.s_addr = htonl(IP_POOL_START + i);
        user_info_table[i].fd = -1;
    }

    struct sockaddr_in6 clientaddr;
    socklen_t client_len = sizeof(clientaddr);
    while (true) {
        nfds = epoll_wait(epfd, events, 20, 500);
        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == listenfd) { //listen event
                logger.info("Reveive listening event");
                clientfd = accept(listenfd, (struct sockaddr *)&clientaddr, &client_len);
                if (clientfd == -1) {
                    // perror("accept failed");
                    logger.error("Accept Listen failed");
                    close(clientfd);
                    exit(-1);
                }
                logger.info("Client fd: %d", clientfd);

                int i = 0;
                pthread_mutex_lock(&mutex);
                for (; i < MAX_USER; ++i) {
                    if (user_info_table[i].fd == -1) {
                        user_info_table[i].fd = clientfd;
                        memcpy(&(user_info_table[i].v6addr), &clientaddr, sizeof(struct sockaddr));
                        user_info_table[i].secs = time(NULL);
                        user_info_table[i].count = 20;
                        break;
                    }
                }
                pthread_mutex_unlock(&mutex);

                if (i == MAX_USER) {
                    logger.error("Cannot accept any more clients");
                    continue;
                }
                i = 0;

                event_add(clientfd);
                char str_addr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(clientaddr.sin6_addr), str_addr, sizeof(str_addr));
                logger.info("A new client %s: %d", str_addr, ntohs(clientaddr.sin6_port));
            } 
            else { 
                if (events[i].data.fd == tunfd) {
                    recv_from_tun();
                } 
                else if (events[i].events & EPOLLIN) {
                    int fd = events[i].data.fd;
                    int user = 0;
                    user = find_user_by_fd(fd);
                    if (user < 0 || user >= MAX_USER) {
                        logger.error("Received a packet from unknown client");
                        continue;
                    }

                    int nread = 0;
                    int tret = ioctl(fd, FIONREAD, &nread);

                    if((tret < 0) || (!nread)) {
                        logger.info("Client %d, disconnected", fd);
                        close(fd);
                        event_del(fd);
                        user_info_table[user].fd = -1;
                        continue;
                    }

                    process_packet_from_client(fd, user);
                }
            }
        }
    }
    close_all();
    return 0;
}
