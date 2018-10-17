/******************************************************************************************************
 * node.h                                                                                             *
 * Description: Node and Iterators class prototypes and implementations.                              *
 * 3/28/13                                                                                            *
 *                                                                                                    *
 * )))~3L1735~(((                                                                                     *
 ******************************************************************************************************/

// Macros
#ifndef NODE_H
#define NODE_H

// Headers
#include <cstdlib>
#include <iterator>
#include <string>

// Node Class Prototypes/Implementations
template<class T> class Node {
public:
	// Typedefs
	typedef T value_type;
	
	// Constructors
	explicit Node(const T &dataIn = T(), Node *linkIn = NULL) : data(dataIn), link(linkIn) {}
	
	// Get Member Functions
	Node* getLink() { return link; }
	T&    getData() { return data; }
	
	// Const Member Functions
	const Node* getLink() const { return link; }
	const T&    getData() const { return data; }
	
	// Set Member Functions
	void setLink(Node *linkIn)    { link = linkIn; }
	void setData(const T &dataIn) { data = dataIn; }

private:
	// Data Members
	T data;
	Node *link;
};

// node_iterator Class Prototypes/Implementations
template<class T>
class node_iterator : public std::iterator<std::forward_iterator_tag, T, std::ptrdiff_t, T*, T&> {
public:
    // Typedefs
    typedef T value_type;
    typedef T& reference;
    typedef T* pointer;
    typedef std::forward_iterator_tag iterator_category;
    typedef std::ptrdiff_t difference_type;

	// Constructors
	explicit node_iterator(Node<T> *initial = NULL) : current(initial) {}
	
	// Overloaded Operators
	reference operator*()  { return current->getData(); }
    pointer   operator->() { return &operator*(); }
	
	node_iterator&      operator++()    { current = current->getLink(); return *this; }            // ++Pre
	const node_iterator operator++(int) { node_iterator oldVal(*this); ++(*this); return oldVal; } // Post++
								  
	bool operator==(const node_iterator &rhs) const { return   current == rhs.current; }
	bool operator!=(const node_iterator &rhs) const { return !(current == rhs.current); }
	
private:
	Node<T> *current;
};

// const_node_iterator Class Prototypes/Implementations
template<class T>
class const_node_iterator : public std::iterator<std::forward_iterator_tag, T, std::ptrdiff_t, const T*, const T&> {
public:
    // Typedefs
    typedef T value_type;
    typedef const T& const_reference;
    typedef const T* const_pointer;
    typedef std::forward_iterator_tag iterator_category;
    typedef std::ptrdiff_t difference_type;   

	// Constructors
	explicit const_node_iterator(const Node<T> *initial = NULL) : current(initial) {}
	
	// Overloaded Operators
	const_reference operator*()  const { return current->getData(); }
    const_pointer   operator->() const { return &operator*(); }
	
	const_node_iterator&      operator++()    { current = current->getLink(); return *this; }                        // ++Pre
	const const_node_iterator operator++(int) { const const_node_iterator oldVal(*this); ++(*this); return oldVal; } // Post++
					
	bool operator==(const const_node_iterator &rhs) const { return   current == rhs.current; }
	bool operator!=(const const_node_iterator &rhs) const { return !(current == rhs.current); }
	
private:
	const Node<T> *current;
};

#endif

