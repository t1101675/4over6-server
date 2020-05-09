#include "server.h"
#include "logger.h"

int epoll;
int listen_fd = -1; //for server to listen
int tun_fd = -1;
Logger logger;
pthread_mutex_t mutex;
pthread_mutex_t sock_lock;

int find_user_by_ip(uint32_t addr) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < MAX_USER; ++i) {
        if ((user_info_table[i].fd != -1) &&
            (user_info_table[i].v4addr.s_addr == addr)) {
            pthread_mutex_unlock(&mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1;
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

int send_keep_alive(int fd) {
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
    int ret = read(tun_fd, msg.data, 1500);
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
            return -1;
        }
        return ret;
    } 
    else if (msg.type == NET_REQUEST) {
        n = sock_receive(fd, msg.data,msg.length - MSG_HEADER_SIZE);
        if (n == msg.length - MSG_HEADER_SIZE) {
            iphdr *hdr = (struct iphdr *)msg.data;
            write(tun_fd, msg.data, MSG_DATA_SIZE(msg));
        }
    } 
    else {
        logger.info("Receive unknown type packet from client %d", fd);
    }
    return 0;
}

struct epoll_event ev, events[20];

void add_ep_event(int fd) {
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &ev);
}

void del_ep_event(int fd) {
    ev.events = EPOLLIN;
    ev.data.fd= fd;
    epoll_ctl(epoll, EPOLL_CTL_DEL, fd, &ev);
}

void setnonblocking(int sock) {
    int opts;
    opts = fcntl(sock, F_GETFL);
    if (opts < 0) {
        logger.error("fcntl(sock,GETFL)");
        exit(1);
    }
    opts = opts | O_NONBLOCK;
    if (fcntl(sock, F_SETFL, opts) < 0) {
        logger.error("fcntl(sock,SETFL,opts)");
        exit(1);
    }
}

int init_server() {
    listen_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (listen_fd == -1) {
        logger.error("Server listening init failed");
        return listen_fd;
    }
    struct sockaddr_in6 server_addr;
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(SERVER_PORT);
    int ret = bind(listen_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (ret == -1) {
        logger.error("Server bind failed");
        close(listen_fd);
        return ret;
    }
    if ((ret = listen(listen_fd, MAX_USER)) < 0) {
        logger.error("Server listen failed");
        return ret;
    }
    setnonblocking(listen_fd);
    del_ep_event(listen_fd);
    return listen_fd;
}

void init_iptable() {
    system("iptables -F");
    system("iptables -t nat -F");
    system("iptables -A FORWARD -j ACCEPT");
    system("iptables -t nat -A POSTROUTING -s 13.8.0.0/8 -j MASQUERADE");
}

int init_tun() {
    char dev_name[IFNAMSIZ];
    strcpy(dev_name, "4o6");
    if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        logger.error("Create tun failed");
        return tun_fd;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags |= IFF_TUN | IFF_NO_PI;

    if (*dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    }

    int ret = 0;
    if ((ret = ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) < 0) {
        logger.error("Set tun device name failed");
        close(tun_fd);
        return ret;
    }

    char buffer[256];
    sprintf(buffer, "ip link set dev %s up", ifr.ifr_name);
    system(buffer);
    sprintf(buffer, "ip a add 13.8.0.1/24 dev %s", ifr.ifr_name);
    system(buffer);
    sprintf(buffer, "ip link set dev %s mtu %u", ifr.ifr_name, 1500);
    system(buffer);

    setnonblocking(tun_fd);
    add_ep_event(tun_fd);

    return ret;
}

void* keep_alive(void*) {
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
                del_ep_event(fd);
            } else {
                user_info_table[i].count -= 1;
                if ( user_info_table[i].count == 0 ) {
                    send_keep_alive(fd);
                    user_info_table[i].count = 20;
                }
            }
        }
    }
}
 
void close_all_fd() {
    if (tun_fd >= 0) {
        close(tun_fd);
    }
    if (listen_fd >= 0) {
        close(listen_fd);
    }
    for (int i = 0; i < MAX_USER; ++i) {
        if (user_info_table[i].fd >= 0) {
            close(user_info_table[i].fd);
        }
    }
}

static void exit_server(int sig) {
    close_all_fd();
    logger.info("Exit");
    exit(0);
}

int main(){
    signal(SIGINT, exit_server);

    epoll = epoll_create(MAX_EPOLL_EVENT);

    int ret = 0;

    if ((ret = init_server()) < 0) {
        exit_server(2);
    }
    if ((ret = init_tun()) < 0) {
        exit_server(2);
    }

    init_iptable();

    logger.info("Server Start, Listening at %d", SERVER_PORT);
    logger.info("Listen fd: %d", listen_fd);
    logger.info("Tun fd: %d", tun_fd);

    // init user_info_table
    for (int i = 0; i < MAX_USER; ++i) {
        user_info_table[i].v4addr.s_addr = htonl(IP_POOL_START + i);
        user_info_table[i].fd = -1;
    }

    // Start keep alive thread
    pthread_t thread_keep_alive;
    pthread_create(&thread_keep_alive, NULL, keep_alive, NULL);
    logger.info("Keep alive thread start");

    int num_ep_wait_fd = 0, clientfd = 0;
    struct sockaddr_in6 clientaddr;
    socklen_t client_len = sizeof(clientaddr);
    while (true) {
        num_ep_wait_fd = epoll_wait(epoll, events, 30, 500);
        
        for (int i = 0; i < num_ep_wait_fd; ++i) {
            if (events[i].data.fd == listen_fd) {
                logger.info("Reveive listening event");
                clientfd = accept(listen_fd, (struct sockaddr *)&clientaddr, &client_len);
                if (clientfd == -1) {
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

                add_ep_event(clientfd);
                char str_addr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(clientaddr.sin6_addr), str_addr, sizeof(str_addr));
                logger.info("A new client %s: %d", str_addr, ntohs(clientaddr.sin6_port));
            } 
            else { 
                if (events[i].data.fd == tun_fd) {
                    recv_from_tun();
                } 
                else if (events[i].events & EPOLLIN) {
                    int fd = events[i].data.fd;
                    int user = find_user_by_fd(fd);

                    if (user < 0 || user >= MAX_USER) {
                        logger.error("Received a packet from unknown client");
                        continue;
                    }

                    int nread = 0;
                    int tret = ioctl(fd, FIONREAD, &nread);

                    if((tret < 0) || (!nread)) {
                        logger.info("Client %d, disconnected", fd);
                        close(fd);
                        del_ep_event(fd);
                        user_info_table[user].fd = -1;
                        continue;
                    }

                    process_packet_from_client(fd, user);
                }
            }
        }
    }
    close_all_fd();
    return 0;
}
