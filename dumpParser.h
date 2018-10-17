/*
 * dumpParser.h
 * Description: Dump parser class protoyepes for sniffed packets.
 * 
 * )))~3L1735~(((
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Macro
#ifndef DUMPPARSER_H
#define DUMPPARSER_H

// Includes
#include <string>
#include <ctime>
#include "forward_list.h"

// dumpParser Class
class DumpParser {
public:
    // Typedefs
    typedef std::string value_type;
    typedef std::size_t size_type;
    typedef DumpParser  self_type;

    // Constructors
    explicit DumpParser(const Forward_List<value_type> &data = Forward_List<value_type>())
        : list(data), recentParse(), current(std::time(0)), recentParseTime(std::time(0)) {} // default

    // Constant Member Functions
    size_type size() const { return list.size(); }
    bool empty()     const { return list.empty(); }
    int save_parser(const char* const path) const;
    void print() const;

    // Modification Member Functions
    void parseFile(const std::string forWhat);
    int  temp_readable_dump(const unsigned char *const buf, const unsigned len);
    int  remove_temp_dump();
    int  fill_parser(const unsigned char *const buf, const unsigned len);
    int  substrFind(std::string pos, std::string word);  
    void remove_non_lines(const std::string word);
    
    // Iterator Functions
    typename Forward_List<value_type>::iterator pos_iter(const unsigned line);
    typename Forward_List<value_type>::const_iterator pos_const_iter(const unsigned line) const;

private:
    // Private Data Members
    Forward_List<value_type> list;
    value_type recentParse;
    std::time_t current, recentParseTime;
};

#endif

