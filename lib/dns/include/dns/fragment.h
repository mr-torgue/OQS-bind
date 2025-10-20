#pragma once 

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <dns/message.h>
#include <dns/request.h>
#include <dns/fcache.h>


// returns the number of fragments for a given message (estimate)
// based on MAX_SIZE for UDP packets (1232 usually)
unsigned get_nr_fragments(dns_message_t *msg);

// checks if msg is a fragment
// expected format: ?fragment_nr?name
// sets the fragment number for msg if fragment
bool is_fragment(isc_mem_t *mctx, dns_message_t *msg);

// fragments a given message msg
// first fragment is returned in msg
// remaining fragments are added to cache
// returns true if success, false otherwise
bool fragment(dns_message_t *msg);

// requests remaining fragments from the name server
// determines how many fragments to retrieve based on the provided response
// sends a request 
bool request_remaining_fragments(dns_request_t *query);