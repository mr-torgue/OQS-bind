/*
QBF has a few limitations:
1. Does NOT work for all messages: 
only DNSKEY and RRSIG resource records are fragmented, thus excluding situations that don't use these records but still exceed the max UDP limit
2. Fragmentation and recombination is complex and error prone:
Fragments cannot simply be concatenated because only certain RR types are fragmented (DNSKEY and RRSIG).
So, every resource record for all fragments need to be matched and should not be mismatched.
For example if a fragment has two keys, a and b, we should make sure that no part of a gets added to b.
Currrently, this matching relies on the order of RR's. BIND9 does not necesarily always keep the order.
3. No distinction between UDP fragmentation and TCP retransmission:
The resolver does not know if a DNS message is a fragment or not if the TC flag is set.


RAW fragmentation does not have these limitations.
It relies on an OPT RR to encode everything.
the flow works as follows:
1. Oversize DNS Response generated
2. Nr of fragments calculated based on body size (e.g. 4000 bytes of data needs 4 fragments)
3. First fragment will carry an OPT record specifying:
    a. number of fragments (1 byte)
4. Resolver will query for the remaining fragments using ?frag_nr?[domain] (no OPT record)
5. Once all fragments have been received, resolver will recombine

Advantages:
1. Works for all messages
2. Simple and effective: we do not require changes to resource records
*/

#include <isc/result.h>
#include <isc/types.h>
#include <dns/message.h>
#include <dns/fcache.h>


// chosen based on https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
#define RAW_OPCODE 7
#define RAW_RCODE 12
#define RAW_OPT_OPTION 22

#define DNS_HEADER_SIZE 12
#define RR_HEADER_SIZE 10
#define QUESTION_HEADER_SIZE 4

unsigned get_nr_fragments(const unsigned max_msg_size, const unsigned total_msg_size, const unsigned header_size, const unsigned question_size, const unsigned opt_size);

isc_result_t raw_fragment(isc_mem_t *mctx, fcache_t *fcache,
                          dns_message_t *msg, char *client_address,
                          const unsigned max_udp_size);


    
isc_result_t raw_reassemble_fragments(isc_mem_t *mctx,
                                      fragment_cache_entry_t *entry,
                                      dns_message_t **out_msg);
