#pragma once 

#include <string.h>
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/types.h>

// key = id + client ip:port
// overwrites keysize to match the string length
void fcache_create_key(dns_messageid_t id, char *client_address, unsigned char *key, unsigned *keysize);

// DNSKEY header: 2 (Flags) + 1 (Protocol) + 1 (Algorithm) = 4 Bytes
unsigned calc_dnskey_header_size(void);

// RRSIG header: 2 (Type Covered) + 1 (Algorithm) + 1 (Labels) + 4 (TTL) + 4 (Expiration) + 4 (Inception) + 2 (Key Tag) + x (Signer Name) = 18 + x
unsigned calc_rrsig_header_size(dns_rdata_t *rdata);

// create a query from a given buffer that represents a dns message
// returns true if a query was created
// NOTE: can be optimized (e.g. remove parsing):
// 1. peek at header to determine flags and id
// 2. peek at query/question to get name
// 3. construct question section 
// 4. construct OPT --> use default values
bool get_fragment_query_raw(isc_mem_t *mctx, isc_buffer_t *buffer, uint fragment_nr, dns_message_t **question, isc_buffer_t **question_buffer);