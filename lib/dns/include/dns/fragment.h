#pragma once 

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <dns/message.h>
#include <dns/request.h>
#include <dns/fcache.h>
#include <dns/fragment_helpers.h>
#include <dns/keyvalues.h>

#define RRSIG 46
#define DNSKEY 48
#define MAXUDP 1232


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
// returns the total message size in bytes 
// num_sig_rr / num_dnskey_rr contain the number of resource records for signatures and keys
// total_sig_rr / total_dnskey_rr contains the total size in bytes
unsigned calc_message_size(dns_message_t *msg,
                       unsigned *num_sig_rr, unsigned *num_dnskey_rr, 
                       unsigned *total_sig_rr, unsigned *total_dnskey_rr, unsigned *savings);

// estimates the size of the complete message based on a fragment
unsigned estimate_message_size(dns_message_t *msg, unsigned *total_sig_bytes, unsigned *total_dnskey_bytes, unsigned *savings);

// for testing purposes
// calculates the start and length for the given resource record
void calculate_start_end(unsigned fragment_nr, unsigned nr_fragments, unsigned offset, unsigned rdata_size, unsigned can_send_first_fragment, unsigned can_send, unsigned total_pk_sig_bytes_per_frag, unsigned rr_pk_sig_count, unsigned *start, unsigned *frag_len);

// fragments a given message msg
// first fragment is returned in msg
// remaining fragments are added to cache
// returns true if success, false otherwise
// TODO: currently has to pass through all rr's twice --> reduce to 1 pass
isc_result_t fragment(isc_mem_t *mctx, fcache_t *fcache, dns_message_t *msg, char *client_address, const unsigned max_udp_size);

// reassembles a given entry into a new dns_message_t
// checks if all fragments are in the entry --> otherwise returns false
// returns:
//   ISC_R_SUCCESS if succesfully reassembled
//   ISC_R_INPROGRESS if not all fragments have been received yet
//   ISC_R_FAILURE if the fragments mismatch (for example, mismatching id)
isc_result_t reassemble_fragments(isc_mem_t *mctx, fcache_t *fcache, unsigned char *key, unsigned keysize, dns_message_t **out_msg);