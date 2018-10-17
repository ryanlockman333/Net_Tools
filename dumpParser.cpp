/*
 * dumpParser.cpp
 * Description: Dump parser class definitions.
 *
 * )))~3L1735~(((
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Includes
#include <fstream>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include "dumpParser.h"

// Constant Member Functions
int DumpParser::save_parser(const char* const path) const {
    // Open File
    std::ofstream ofs(path);
    if(!ofs) {
        std::cerr << "\nError, opening file for writing.\n";
        return -1;
    }

    // Set Current Time for Countdown
    std::time((std::time_t*)&current);   

    // Loop Out Data
    typename Forward_List<value_type>::const_iterator b = list.cbegin(), e = list.cend();
    for(; b != e; ++b) {
             //if(*b != recentParse)
            //if(std::difftime(current, recentParseTime) >= 5)
                //ofs << *b << '\n';
            ofs << *b << '\n';
    }
    
    ofs.close(); // close file
    return 0;
}

void DumpParser::print() const {
    if(!empty()) {
        typename Forward_List<value_type>::const_iterator b = list.cbegin(), e = list.cend();
        for(unsigned count = 0; b != e; std::cout << ++count << "] " << *b++ << "\n");
    }
}

// Modification Member Functions
void DumpParser::parseFile(const std::string forWhat) {
    remove_non_lines(forWhat);   // remove unassociated lines
}

int DumpParser::temp_readable_dump(const unsigned char *const buf, const unsigned len) {
     // Open Temp File
    std::ofstream ofs("tempDump");
    if(!ofs) {
        std::cerr << "\nError, openning file for reading.\n";
        return -1;
    }
    
    // Temp Buffer
    char *rdump = (char*)buf;

    // Decode Into Human Readable Form
    for(std::size_t i = 0; i < std::strlen(rdump); ++i) {
        unsigned char c = rdump[i];
        if((c > 0) && (c < 127)) // readable ASCII
            ofs << c;
    }
    ofs.close(); // close temp file

    return 0;
}

int DumpParser::remove_temp_dump() {
    // Unlink Filename
    if(unlink("tempDump"))
        return -1;

    return 0;
}

int DumpParser::fill_parser(const unsigned char *const buf, const unsigned len) {
    // Temp Dump For Readable Form
    temp_readable_dump(buf, len);

    // Open Temp File
    std::ifstream ifs("tempDump");
    if(!ifs) {
        std::cerr << "\nError, openning file for reading.\n";
        return -1;
    }
    
    // Fill List, Comes In Reverse
    Forward_List<value_type> reverse;
    value_type vBuf;
    while(ifs.good() && ifs.peek() != EOF) {
        std::getline(ifs, vBuf, '\n');
        reverse.push_front(vBuf);
    }
    
    ifs.close();           // close temp file
    if(remove_temp_dump()) // delete file
        return -1;

    // Reverse List For Correct Order
    while(!reverse.empty()) {
        list.push_front(reverse.front());
        reverse.pop_front();
    }

    return 0;
}

// Helper Functions
int DumpParser::substrFind(std::string pos, std::string word) {
    std::size_t posU = pos.find(word);
    if(posU == std::string::npos)
        return -1;
}

void DumpParser::remove_non_lines(const std::string word) {
    // Loop List
    for(typename Forward_List<value_type>::iterator b = list.begin(), e = list.end(); b != e; ++b) {
        std::size_t found = b->find(word);
        if(found == std::string::npos)   // not found
            list.erase_one(*b);          // remove
        else {
            recentParse = *b;
            std::time(&recentParseTime); // set last parse time
        }
    }
}

typename Forward_List<DumpParser::value_type>::iterator DumpParser::pos_iter(const unsigned line) {
    // Position Iterator
    unsigned count = 0;   
    typename Forward_List<value_type>::iterator b = list.begin(), e = list.end();
    
    for(; b != e && ++count < line; ++b);

    return b;
}

typename Forward_List<DumpParser::value_type>::const_iterator DumpParser::pos_const_iter(const unsigned line) const {
    // Position Iterator
    unsigned count = 0;   
    typename Forward_List<value_type>::const_iterator b = list.cbegin(), e = list.cend();
    
    for(; b != e && ++count < line; ++b)

    return b;
}

