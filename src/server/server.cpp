#include "server.h"
#include "logger.h"

int epoll = -1;
int listen_fd = -1; //for server to listen
int tun_fd = -1;
Logger logger;
pthread_mutex_t mutex;
struct epoll_event ep_ev, events[30];

// use ip addr to find users
int find_user_by_ip(uint32_t addr) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < MAX_USER_NUM; ++i) {
        if ((user_info_table[i].fd != -1) &&
            (user_info_table[i].v4addr.s_addr == addr)) {
            pthread_mutex_unlock(&mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1;
}

// user ids to find users
int find_user_by_fd(int fd) {
    if (fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < MAX_USER_NUM; ++i) {
        if (user_info_table[i].fd == fd) {
            pthread_mutex_unlock(&mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1;
}

// send keep alive package
int send_keep_alive(int fd) {
    logger.info("Send KEEPALIVE packet to %d", fd);
    Msg msg;
    msg.type = KEEPALIVE;
    msg.length = HEADER_SIZE;
    int ret;
    pthread_mutex_lock(&mutex);
    ret = send(fd, &msg, msg.length, 0);
    pthread_mutex_unlock(&mutex);
    return ret;
}

// send ip response to client
int ip_response(int fd, int user) {
    logger.info("Send IP_RESPONSE packet to %d", fd);
    char ip_str[16];
    inet_ntop(AF_INET, &(user_info_table[user].v4addr), ip_str, 16);
    
    Msg msg;
    msg.type = IP_RESPONSE;
    sprintf(msg.data ,"%s 0.0.0.0 202.38.120.242 8.8.8.8 202.106.0.20", ip_str);
    msg.length = strlen(msg.data) + HEADER_SIZE + 1;
    
    int ret;
    pthread_mutex_lock(&mutex);
    ret = send(fd, &msg, msg.length, 0);
    pthread_mutex_unlock(&mutex);
    return ret;
}

// receive packet from client
int recv_from_client(int fd, char* buff, int n) {
    int left = n;
    pthread_mutex_lock(&mutex);
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
    pthread_mutex_unlock(&mutex);
    return n;
}

// receive packet from tun
void recv_from_tun() {
    struct Msg msg;
    int read_size = read(tun_fd, msg.data, 1500);
    if (read_size <= 0) {
        logger.error("Read packet to tun failed");
        return;
    }

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

    int msg_length = read_size + HEADER_SIZE;
    //send the packet back to client
    if (ip_head->version == 4) {
        msg.type = NET_RESPONSE;
        msg.length = msg_length;
        pthread_mutex_lock(&mutex);
        if((send(fd, &msg, msg.length, 0)) < 0) {
            pthread_mutex_unlock(&mutex);
            logger.error("Send to client %s failed", daddr);
            return;
        }
        pthread_mutex_unlock(&mutex);
    }
}

// receive and read the packet from client
int process_packet_client_packet(int fd, int user) {
    if (fd < 0) {
        return -1;
    }

    struct Msg msg;
    int n = recv_from_client(fd, (char*)&msg, HEADER_SIZE);

    if (n <= 0){
        logger.error("Receive from client %d failed", fd);
        close(fd);
        for (int i = 0; i < MAX_USER_NUM; ++i) {
            if (user_info_table[i].fd == fd) {
                user_info_table[i].fd = -1;
            }
        }
        return -1;
    }

    if (msg.type == KEEPALIVE) {
        user_info_table[user].secs = time(0);
        logger.info("Receive a keepalive packet from client %d", fd);
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
        n = recv_from_client(fd, msg.data,msg.length - HEADER_SIZE);
        if (n == DATA_SIZE(msg)) {
            iphdr *hdr = (struct iphdr *)msg.data;
            // send to internet via tun
            write(tun_fd, msg.data, DATA_SIZE(msg));
        }
    } 
    else {
        logger.info("Receive unknown type packet from client %d", fd);
    }
    return 0;
}

void add_ep_event(int fd) {
    ep_ev.events = EPOLLIN;
    ep_ev.data.fd = fd;
    epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &ep_ev);
}

void del_ep_event(int fd) {
    ep_ev.events = EPOLLIN;
    ep_ev.data.fd= fd;
    epoll_ctl(epoll, EPOLL_CTL_DEL, fd, &ep_ev);
}

// Refer to https://github.com/chwangthu/4over6/
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
    
    struct sockaddr_in6 server_addr6;
    server_addr6.sin6_addr = in6addr_any;
    server_addr6.sin6_port = htons(SERVER_PORT);
    server_addr6.sin6_family = AF_INET6;

    int ret = bind(listen_fd, (struct sockaddr *) &server_addr6, sizeof(server_addr6));
    if (ret == -1) {
        logger.error("Server bind failed");
        close(listen_fd);
        return ret;
    }
    if ((ret = listen(listen_fd, MAX_USER_NUM)) < 0) {
        logger.error("Server listen failed");
        return ret;
    }
    setnonblocking(listen_fd);
    add_ep_event(listen_fd);
    return listen_fd;
}

void init_network() {
    system("iptables -F");
    system("iptables -t nat -F");
    system("echo \"1\" > /proc/sys/net/ipv4/ip_forward");
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

    // set new tun dev
    char cmd[100];
    sprintf(cmd, "ip link set dev %s up", ifr.ifr_name);
    system(cmd);
    
    sprintf(cmd, "ip a add 13.8.0.1/24 dev %s", ifr.ifr_name);
    system(cmd);
    
    sprintf(cmd, "ip link set dev %s mtu %u", ifr.ifr_name, 1500);
    system(cmd);

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
        for (int user_i = 0; user_i < MAX_USER_NUM; ++user_i) {
            int client_fd = user_info_table[user_i].fd;
            if (client_fd < 0) {
                continue;
            }

            int time_diff = time(0) - user_info_table[user_i].secs;
            if (time_diff > 60) {
                logger.info("Timeout, remove client %d", client_fd);
                user_info_table[user_i].fd = -1;
                del_ep_event(client_fd);
                close(client_fd);
            } 
            else {
                user_info_table[user_i].count--;

                if (user_info_table[user_i].count == 0) {
                    user_info_table[user_i].count = 20;
                    send_keep_alive(client_fd);
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
    if (epoll >= 0) {
        close(epoll);
    }
    for (int i = 0; i < MAX_USER_NUM; ++i) {
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

    init_network();

    logger.info("Server Start, Listening at %d", SERVER_PORT);
    logger.info("Listen fd: %d", listen_fd);
    logger.info("Tun fd: %d", tun_fd);

    // init user info table
    for (int i = 0; i < MAX_USER_NUM; ++i) {
        user_info_table[i].v4addr.s_addr = htonl(IP_POOL_START + i);
        user_info_table[i].fd = -1;
    }

    // Start keep alive thread
    pthread_t thread_keep_alive;
    pthread_create(&thread_keep_alive, NULL, keep_alive, NULL);
    logger.info("Keep alive thread start");

    int num_ep_wait_fd = 0, client_fd = 0;
    struct sockaddr_in6 client_addr6;
    socklen_t client_len = sizeof(client_addr6);
    while (true) {
        num_ep_wait_fd = epoll_wait(epoll, events, 30, 500);
        // for every event in epoll
        for (int ev_i = 0; ev_i < num_ep_wait_fd; ++ev_i) {
            if (events[ev_i].data.fd == listen_fd) {
                logger.info("Reveive listening event");
                client_fd = accept(listen_fd, (struct sockaddr *)&client_addr6, &client_len);
                if (client_fd < 0) {
                    logger.error("Accept Listen failed");
                    close(client_fd);
                    exit_server(2);
                }
                logger.info("Client fd: %d", client_fd);

                int user_i = 0;
                pthread_mutex_lock(&mutex);
                for (; user_i < MAX_USER_NUM; ++user_i) {
                    if (user_info_table[user_i].fd < 0) {
                        user_info_table[user_i].fd = client_fd;
                        user_info_table[user_i].count = 20;
                        user_info_table[user_i].secs = time(0);
                        memcpy(&(user_info_table[user_i].v6addr), &client_addr6, sizeof(struct sockaddr));
                        break;
                    }
                }
                pthread_mutex_unlock(&mutex);

                if (user_i >= MAX_USER_NUM) {
                    logger.error("Cannot accept any more clients");
                    continue;
                }

                char addr6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(client_addr6.sin6_addr), addr6, sizeof(addr6));
                
                add_ep_event(client_fd);
                
                logger.info("A new client %s: %d", addr6, ntohs(client_addr6.sin6_port));
            } 
            else { 
                if (events[ev_i].data.fd == tun_fd) {
                    recv_from_tun();
                } 
                else if (events[ev_i].events & EPOLLIN) {
                    int fd = events[ev_i].data.fd;
                    int user = find_user_by_fd(fd);

                    if (user < 0 || user >= MAX_USER_NUM) {
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

                    process_packet_client_packet(fd, user);
                }
            }
        }
    }

    close_all_fd();
    
    return 0;
}
