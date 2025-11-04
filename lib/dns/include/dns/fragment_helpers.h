#pragma once 

#include <string.h>
#include <isc/util.h>
#include <dns/rdata.h>
#include <dns/types.h>

// key = id + client ip:port
// overwrites keysize to match the string length
static void fcache_create_key(dns_messageid_t id, char *client_address, unsigned char *key, unsigned *keysize) {
    REQUIRE(*keysize >= 64);
    int tmp = snprintf((char *)key, *keysize, "%x-%s", id, client_address);
    *keysize = tmp > 0 ? (unsigned)tmp : *keysize; // set keysize to string length
}

// DNSKEY header: 2 (Flags) + 1 (Protocol) + 1 (Algorithm) = 4 Bytes
static unsigned calc_dnskey_header_size(void) {
    return 4;
}

// RRSIG header: 2 (Type Covered) + 1 (Algorithm) + 1 (Labels) + 4 (TTL) + 4 (Expiration) + 4 (Inception) + 2 (Key Tag) + x (Signer Name) = 18 + x
static unsigned calc_rrsig_header_size(dns_rdata_t *rdata) {
    unsigned header_size = 18;  
    //signer's name length is variable
    while (rdata->data[header_size] != 0 && header_size < rdata->length) {
        header_size++;
    }
    return ++header_size;
}