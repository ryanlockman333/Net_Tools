/********************************************************************************************* 
 * forward_list.h                                                                            *
 * Description: Forward_List Template Class prototypes.                                      *
 * 4/16/14                                                                                   *
 *                                                                                           *
 * )))~3L1735~((((                                                                           *
 *********************************************************************************************/

// Macros
#ifndef FORWARD_LIST_H
#define FORWARD_LIST_H

// Headers
#include <iosfwd>
#include <cstdlib>
#include "node.h"

// Forward Declarations for Operator<<
template<typename T> class Forward_List;
template<typename T> std::ostream& operator<<(std::ostream&, const Forward_List<T>&);

// Forward_List Class
template <typename T> class Forward_List {
public:
// Typedefs
    typedef T value_type;
    typedef std::size_t size_type;
    typedef Forward_List<T> self_type;

    // Node Iterator
    typedef node_iterator<T> iterator;
    typedef typename iterator::reference reference;
    typedef typename iterator::pointer pointer;
    typedef typename iterator::iterator_category iterator_category;
    typedef typename iterator::difference_type difference_type;

    // Const Node Iterator
    typedef const_node_iterator<T> const_iterator;
    typedef typename const_iterator::const_reference const_reference;
    typedef typename const_iterator::const_pointer const_pointer;
    typedef typename const_iterator::iterator_category const_iterator_category;
    typedef typename const_iterator::difference_type const_difference_type;

// Constructors
    Forward_List() : head(NULL), used(0) {}                                    // default
    // Post: Initializes data members.
    Forward_List(const self_type &rhs) : head(NULL), used(0) { copy(rhs); }    // copy
    // Post: Initializes data members to that of right handed sign.
    template<typename Iterator> Forward_List(Iterator b, Iterator e);          // itererator range copy
    // Post: Initializes data members in the ranger of iterator [b,e].
    ~Forward_List() { clear(); }                                               // destructor
    // Post: Calls the destructor to deallocate data members.

// Overloaded Assignment
    void operator=(const self_type &rhs);
    // Post: Replaces data members with that of right handed sign.

// Constant Member Functions
    size_type size() const { return used; }
    // Post: Returns size of list.
    bool empty()     const { return !head; }
    // Post: Returns ture if data is empty, false otherwise.
    const T& front() const;
    // Pre:  List must not be empty.
    // Post: Returns front node data of list.
    const bool contains(const T &target) const;
    // Post: Returns true if target is in list, false otherwise.
    const int get_member_pos(const T &target) const;
    // Post: Returns position of target if in list, -1 otherwise
    const T get_data_pos(const unsigned pos) const;
    // Post: Returns data at pos if in list, T() default destructor to compare to otherwise

// Modification Member Funtions
    void push_front(const T &entry);
    // Post: Inserts data entry into front of list.
    void pop_front();
    // Pre:  List must not be empty.
    // Post: Removes the first element of the list.
    bool erase_one(const T &target);
    // Post: Removes first occurence of data target if there, returns true if succeeded, false otherwise.
    unsigned erase(const T &target);
    // Post: Removes all occurences of data target if there.
    void clear();
    // Post: Resets list to an empty state.
    iterator find(const T &target);
    // Post: Returns an iterator to the specified data target if there, otherwise end() is returned.
    const_iterator const_find(const T &target);
    // Post: Returns an iterator to the specified data target if there, otherwise end() is returned.
    void insert_after(iterator it, const T &target);
    // Post: Inserts the specified data target into list after specified iterator.
    bool remove_after(iterator it);
    // Post: Removes element after specified iterator adn returns true, otherwise false.
    template<typename Iterator> void insert_after(iterator it, Iterator b, Iterator e);
    // Post: Inserts the specified data range of Iterator [b, e), after the specified iterator it.
    void remove_range(iterator b, iterator e);
    // Post: Removes the specified data range of iterator [b, e).
    void reverse();
    // Post: Reverses the list.

// Friends
    // Overloaded Operators
    friend std::ostream& operator<< <T>(std::ostream& os, const Forward_List<T> &rhs);
    // Post: Prints the data contents of the list via the operator.

// Iterator Functions
    iterator begin() { return iterator(head); }
    // Post: Returns a non const iterator to the first element of the list.
	iterator end()   { return iterator(); }
    // Post: Returns a non const iterator to one past the last element of the list.
	const_iterator cbegin() const { return const_iterator(head); }
    // Post: Returns a const iterator to the first element of the list.
	const_iterator cend()   const { return const_iterator(); }
    // Post: Returns a const iterator to one past the last element of the list.
	
private:
// Data Members
    Node<T> *head;
    size_type used;

    // Helper Functions
    void copy(const self_type &rhs);
};

#include "forward_list.tem"
#endif

