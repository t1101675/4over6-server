#include "server.h"
#include "logger.h"

Logger logger;

// find
int find_user_by_ip(uint32_t addr);
int find_user_by_fd(int fd);

// keep alive
void* keep_alive(void*);

// process request
pthread_mutex_t mutex;
pthread_mutex_t mutex_net;
int ip_response(int fd, int user);
int recv_from_client(int fd, char* data, int n);
int recv_from_tun();
int process_client_packet(int fd, int user);
void set_user(int user_id, int client_fd, int count, int secs, struct sockaddr_in6 client_addr6);

// epoll
int epoll = -1;
struct epoll_event ep_ev, events[30];
void add_ep_event(int fd);
void del_ep_event(int fd);

// init
int tun_fd = -1;
int listen_fd = -1;
int set_fd_not_block(int sock);
int init_server();
void init_network();
int init_tun();

// quit
void close_all_fd();
static void exit_server(int sig);


int main(int argc, char*argv[]) {
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
        if (epoll < 0) {
            logger.error("Epoll Error");
            break;
        }
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
                logger.info("Comming client's fd: %d", client_fd);

                int user_i = 0;
                // finding a user should be atomic
                pthread_mutex_lock(&mutex);
                for (; user_i < MAX_USER_NUM; ++user_i) {
                    if (user_info_table[user_i].fd < 0) {
                        set_user(user_i, client_fd, 20, time(0), client_addr6);
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
                
                logger.info("A new client has connected, (v6 addr: port) %s: %d", addr6, ntohs(client_addr6.sin6_port));
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

                    process_client_packet(fd, user);
                }
            }
        }
    }

    close_all_fd();
    
    return 0;
}


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

// send ip response to client
int ip_response(int fd, int user) {
    logger.info("Send IP_RESPONSE packet to %d", fd);
    char ip_str[16];
    inet_ntop(AF_INET, &(user_info_table[user].v4addr), ip_str, 16);
    
    Msg msg;
    msg.type = IP_RESPONSE;
    sprintf(msg.data ,"%s 0.0.0.0 202.38.120.242 8.8.8.8 202.106.0.20", ip_str);
    // "+1" is very imprtant !!!
    msg.length = strlen(msg.data) + HEADER_SIZE + 1;

    pthread_mutex_lock(&mutex_net);
    int ret = send(fd, &msg, msg.length, 0);
    pthread_mutex_unlock(&mutex_net);
    return ret;
}

// receive packet from client
int recv_from_client(int fd, char* data, int n) {
    int temp_n = n;
    pthread_mutex_lock(&mutex_net);
    while (temp_n > 0) {
        ssize_t recv_size = recv(fd, data + n - temp_n, temp_n, 0);
        if (recv_size < 0) {
            return -1;
        } 
        else if (recv_size > 0) {
            temp_n -= recv_size;
        } 
        else if (recv_size == 0) {
            return 0;
        } 
        else {
            logger.error("sock_receive error");
            return -1;
        }
    }
    pthread_mutex_unlock(&mutex_net);
    return n;
}

// receive packet from tun
int recv_from_tun() {
    struct Msg msg;
    int read_size = read(tun_fd, msg.data, 1500);
    if (read_size <= 0) {
        logger.error("Read packet to tun failed");
        return -1;
    }

    struct iphdr *ip_head = (struct iphdr *)msg.data;
    char saddr[16];
    inet_ntop(AF_INET, &ip_head->saddr, saddr, sizeof(saddr));
    char daddr[16];
    inet_ntop(AF_INET, &ip_head->daddr, daddr, sizeof(daddr));
    
    int user = find_user_by_ip(ip_head->daddr);
    if (user < 0) {
        logger.error("Cannot find client %s", daddr);
        return -1;
    }

    assert(user_info_table[user].fd != -1);
    assert(user_info_table[user].v4addr.s_addr == ip_head->daddr);

    int fd = user_info_table[user].fd;

    int msg_length = read_size + HEADER_SIZE;
    //send the packet back to client
    if (ip_head->version == 4) {
        int ret = 0;
        msg.type = NET_RESPONSE;
        msg.length = msg_length;
        pthread_mutex_lock(&mutex_net);
        if((ret = send(fd, &msg, msg.length, 0)) < 0) {
            pthread_mutex_unlock(&mutex_net);
            logger.error("Send to client %s failed", daddr);
            return ret;
        }
        pthread_mutex_unlock(&mutex_net);
    }
    return 0;
}

// receive and read the packet from client
int process_client_packet(int fd, int user) {
    if (fd < 0) {
        return -1;
    }

    struct Msg msg;
    int n = recv_from_client(fd, (char*)&msg, HEADER_SIZE);

    if (n <= 0){
        logger.error("Receive from client %d failed", fd);
        close(fd);
        int user_id = find_user_by_fd(fd);
        if (user_id >= 0) {
            user_info_table[user_id].fd = -1;
        }
        return -1;
    }

    if (msg.type == KEEPALIVE) {
        user_info_table[user].secs = time(0);
        logger.info("Receive a keepalive packet from client %d", fd);
    }
    else if (msg.type == NET_REQUEST) {
        n = recv_from_client(fd, msg.data, msg.length - HEADER_SIZE);
        if (n == DATA_SIZE(msg))
        {
            iphdr *hdr = (struct iphdr *)msg.data;
            // send to internet via tun
            write(tun_fd, msg.data, DATA_SIZE(msg));
        }
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
    else {
        logger.info("Receive unknown type packet from client %d", fd);
    }
    return 0;
}

void set_user(int user_id, int client_fd, int count, int secs, struct sockaddr_in6 client_addr6){
    user_info_table[user_id].fd = client_fd;
    user_info_table[user_id].count = 20;
    user_info_table[user_id].secs = time(0);
    memcpy(&(user_info_table[user_id].v6addr), &client_addr6, sizeof(struct sockaddr));
}

void *keep_alive(void *) {
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

                    logger.info("Send KEEPALIVE packet to %d", client_fd);
                    Msg msg;
                    msg.type = KEEPALIVE;
                    msg.length = HEADER_SIZE;
                    pthread_mutex_lock(&mutex_net);
                    send(client_fd, &msg, msg.length, 0);
                    pthread_mutex_unlock(&mutex_net);
                }
            }
        }
    }
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

int set_fd_not_block(int sock) {
    int opts = fcntl(sock, F_GETFL);
    if (opts < 0) {
        logger.error("fcntl(sock,GETFL)");
        return -1;
    }
    opts = opts | O_NONBLOCK;
    if (fcntl(sock, F_SETFL, opts) < 0) {
        logger.error("fcntl(sock,SETFL,opts)");
        return -1;
    }
    return 0;
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

    int ret = 0;
    if ((ret = bind(listen_fd, (struct sockaddr *) &server_addr6, sizeof(server_addr6))) < 0) {
        logger.error("Server bind failed");
        return ret;
    }
    if ((ret = listen(listen_fd, MAX_USER_NUM)) < 0) {
        logger.error("Server listen failed");
        return ret;
    }

    if ((ret = set_fd_not_block(listen_fd)) < 0) {
        return ret;
    }
    
    add_ep_event(listen_fd);
    return listen_fd;
}

void init_network() {
    system("echo \"1\" > /proc/sys/net/ipv4/ip_forward");
    system("iptables -F");
    system("iptables -t nat -F");
    system("iptables -A FORWARD -j ACCEPT");
    system("iptables -t nat -A POSTROUTING -s 13.8.0.0/8 -j MASQUERADE");
}

// https://zhaohuabing.com/post/2020-02-24-linux-taptun/
int init_tun() {
    char dev_name[IFNAMSIZ];
    strcpy(dev_name, "4o6");
    if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        logger.error("Creating tun dev failed");
        return -1;
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

    if ((ret = set_fd_not_block(tun_fd)) < 0) {
        return ret;
    }
    add_ep_event(tun_fd);

    return ret;
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

