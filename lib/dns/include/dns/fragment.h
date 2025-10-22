#pragma once 

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <dns/message.h>
#include <dns/request.h>
#include <dns/fcache.h>

#define RRSIG 46
#define DNSKEY 48


#define is_fragment(a, b) is__fragment(a, b, true) 
#define is_fragment_noforce(a, b) is__fragment(a, b, false) 
// checks if msg is a fragment
// expected format: ?fragment_nr?name
// sets the fragment number for msg if fragment
// if force is set, the logic re-checks the msg regardless if msg->is_fragment is true
bool is__fragment(isc_mem_t *mctx, dns_message_t *msg, bool force);

// returns the number of fragments for a given message
// max_msg_size is the maximum packet size
// total_msg_size is the size of the complete DNS message
// total_sig_pk_bytes are all the signature and key bytes (only these RR's get fragmented)
// savings indicates the amount of extra bytes fragments 2..n have, due to the fact that we can omit some data (AFAIK)
// returns the number of fragments needed and the fragment sizes in bytes
unsigned get_nr_fragments(const unsigned max_msg_size, const unsigned total_msg_size, const unsigned total_sig_pk_bytes, const unsigned savings, unsigned *can_send_first_msg, unsigned *can_send);


// calculates all the sizes needed for fragmentation
bool calc_message_size(dns_message_t *msg, unsigned *msg_size, unsigned *answer_sizes, unsigned *authoritative_sizes, unsigned *additional_sizes, unsigned *num_sig_rr, unsigned *num_dnskey_rr, unsigned *total_sig_rr, unsigned *total_dnskey_rr, unsigned *savings);

// estimates the size of the complete message based on a fragment
bool estimate_message_size(dns_message_t *frag, unsigned *msg_size, unsigned *answer_sizes, unsigned *authoritative_sizes, unsigned *additional_sizes, unsigned *num_sig_rr, unsigned *num_dnskey_rr, unsigned *total_sig_rr, unsigned *total_dnskey_rr, unsigned *savings);

// fragments a given message msg
// first fragment is returned in msg
// remaining fragments are added to cache
// returns true if success, false otherwise
// TODO: currently has to pass through all rr's twice --> reduce to 1 pass
bool fragment(dns_message_t *msg);

// requests remaining fragments from the name server
// determines how many fragments to retrieve based on the provided response
// sends a request 
bool request_remaining_fragments(dns_request_t *query);