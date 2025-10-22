#include "include/dns/fragment.h"
#include <isc/util.h>
#include <dns/fragment.h>
#include <dns/types.h>

// key = id + client ip:port
static void fcache_create_key(dns_messageid_t id, char *client_address,unsigned client_address_size, unsigned char *buffer, unsigned bufsize) {
    REQUIRE(bufsize >= sizeof(id) + client_address_size);
    memcpy(buffer, &id, sizeof(id));
    memcpy(buffer + sizeof(id), &client_address, client_address_size);
}

bool is__fragment(isc_mem_t *mctx, dns_message_t *msg, bool force) {
    // check if already done
    if (msg->is_fragment && !force) {
        return true;
    }
    // check if it has name in the question section
    if(dns_message_firstname(msg, DNS_SECTION_QUESTION) != ISC_R_SUCCESS) {
        return false;
    }
    // set default values
    // will get overwritten if valid fragment
    bool success = false;
    msg->fragment_nr = 0;
    msg->is_fragment = false;
    // names are compressed use dns_name_tostring to get decompressed string
    char *qname = NULL;
    dns_name_tostring(msg->cursors[DNS_SECTION_QUESTION], &qname, mctx);

    // should start with '?'
    if (qname[0] == '?') {
        int i = 1;
        int qname_len = strlen(qname);
        // find second '?'
        for (; i < qname_len; i++) {
            if (qname[i] == '?') {
                break;
            }
        }

        // second '?' not found
        if (i == qname_len) {
		    fprintf(stderr, "not a valid fragment for qname %s", qname);
            success = false;
        }
        else {
            // parse fragment number
            char *frag_str = isc_mem_get(mctx, i * sizeof(char)); // include space for \0
            strncpy(frag_str, qname + 1, i -1);
            frag_str[i - 1] = '\0';
            char* end;
            unsigned long nr = strtoul(frag_str, &end, 10);
            if (frag_str == end) {
                fprintf(stderr, "fragment number could not be parsed for qname %s", qname);
                success = false;
            }
            else if (*end != '\0') {
                fprintf(stderr, "incorrect fragment number ensure format is ?[nr]?[qname]\n");
                success = false;
            }
            else {
                // fragment found, set msg values
                msg->fragment_nr = nr;
                msg->is_fragment = true;
                // TODO: parse qname
                success = true;
            }
            // free memory
            isc_mem_put(mctx, frag_str, i * sizeof(char));
        }
    }
    isc_mem_free(mctx, qname);
    return success;
}

bool calc_message_size(dns_message_t *msg, unsigned *msg_size, 
                       unsigned *section_sizes, unsigned nr_sections,
                       unsigned *answer_sizes, unsigned *authoritative_sizes, unsigned *additional_sizes, 
                       unsigned *num_sig_rr, unsigned *num_dnskey_rr, 
                       unsigned *total_sig_rr, unsigned *total_dnskey_rr, unsigned *savings) {
    REQUIRE(nr_sections == DNS_SECTION_MAX);
    *msg_size = msg->buffer->used;
    for(unsigned i = 0; i < DNS_SECTION_MAX; i++) {
        section_sizes[i] = msg->sections
    }

}


unsigned get_nr_fragments(const unsigned max_msg_size, const unsigned total_msg_size, const unsigned total_sig_pk_bytes, const unsigned savings, unsigned *can_send_first_msg, unsigned *can_send) {
    REQUIRE(total_msg_size > total_sig_pk_bytes); 
    unsigned num_fixed_bytes = total_msg_size - total_sig_pk_bytes;
    REQUIRE(max_msg_size > num_fixed_bytes); // fixed bytes should fit in a message
    *can_send = max_msg_size - num_fixed_bytes;
    *can_send_first_msg = *can_send;

    int qname_overhead = 4;     // ?fragnum? overhead. Assuming fragnum to be at most 2 digits.
    unsigned nr_fragments = 0;

    unsigned counter = 0;
    while (total_sig_pk_bytes > counter) {
        counter += *can_send;
        if (nr_fragments == 0) {
            *can_send += savings;
            *can_send -= qname_overhead; // nr_fragments / 10
        }
        nr_fragments++;
        REQUIRE(nr_fragments < 100); // just to make sure qname_overhead is correct
    }
    return nr_fragments;
}


bool fragment(dns_message_t *msg) {
    unsigned nr_fragments = get_nr_fragments(msg);
    if (nr_fragments == 1) {
        fprintf(stderr, "DNSMessage does not need UDP fragmentation!\n");
        return false;
    }

    // adding fragment to cache
    for (unsigned i = 0; i < nr_fragments; i++) {
        isc_buffer_t *frag;
        frag = copy(msg->buffer);
        for (section) {
            for (rrset) {
                for (rr) {
                    if (rr == DNSKEY) {

                    }
                    else if (rr == RRSIG) {

                    }
                    // exclude because these RR's are sent in first fragment
                    else if (i > 0) {

                    }
                    else {

                    }
                }
            }
        }

        printf("adding fragment %d to the fcache!\n", i);
        dns_message_t *frag;
        unsigned char *key;
        unsigned int keysize;
        fcache_add(key, keysize, frag, nr_fragments);
    }
    
    // change first fragment so it fits in one packet

    return true;

}


// reassembles the complete message from cache
// assumption: cache contains all fragments
// assumption: size of fragments should add up to size specified in entry
static bool reassemble_fragments(fragment_cache_entry_t *entry, dns_message_t *out_msg) {
    REQUIRE(entry->bitmap == ~0);
    isc_buffer_t *msg_buf;
    isc_buffer_allocate(frag_mctx, &msg_buf, entry->size);
    unsigned offset = 0;
    for(unsigned i = 0; i < entry->nr_fragments; i++) {
        isc_region_t region;
        region.base = entry->fragments[i]->base;
        region.length = entry->fragments[i]->used;
        isc_buffer_copyregion(msg_buf + offset, &region);
        offset += entry->fragments[i]->used;
    }
    REQUIRE(offset == entry->size);
    // set ignore TC flag
    unsigned options = DNS_MESSAGEPARSE_IGNORETRUNCATION;
    dns_message_parse(out_msg, msg_buf, options);
}
/*
// callback function for received fragments
static void frag_cb(dns_request_t *request, isc_result_t result, dns_message_t *response, void *arg)  {
    REQUIRE(is_fragment(response)); // will set required metadata
    isc_sockaddr_t *peer_address = (isc_sockaddr_t *)arg;
    char addr_buf[ISC_SOCKADDR_FORMATSIZE];
    isc_sockaddr_format(peer_address, addr_buf, sizeof(addr_buf));

    // check if successful
    if (result == ISC_R_SUCCESS && response != NULL) {
        // create a new key and lookup in cache
        unsigned keysize = sizeof(response->id) + sizeof(addr_buf);
        char key[keysize];
        fcache_create_key(response->id, addr_buf, key, keysize);
        fragment_cache_entry_t entry;

        // check if in cache
        if (isc_ht_find(fragment_cache, key, keysize, (void **)&entry) == ISC_R_SUCCESS) {   
            // check if bitmap is all 1's
            if (entry.bitmap == ~0) {
                dns_message_t *complete_msg;
                reassemble_fragments(complete_msg);
                // go to???
            }
        }
        else {
            printf("No entry for key %s in fragment cache!", key);
        }
    }
    else {
        printf("Request failed: %s\n", isc_result_totext(result));
    }
}


//This function is triggered on the first fragment it receives (resolver)
bool request_fragments(resquery_t *query,) {
    unsigned nr_fragments = get_nr_fragments(frag);
    printf("Adding first fragment to cache...");
    add_to_cache(dns_message_t *msg, dns_cache_t *cache);
    printf("Requesting %d additional fragments...", nr_fragments - 1);
    for (int i = 2; i <= nr_fragments; i++) {
        dns_request_t *request = NULL;
        // copy requst

        dns_request_create(
            &request,
            dns_rdataclass_in,
            dns_rdatatype_a,
            "example.com",
            query_callback,
            NULL,
            NULL,
            NULL,
            NULL,
            0,
            NULL,
            NULL,
            &cb,
            msg->id,
            0
        );
        // Send the request
        dns_request_send(&request);
    }
}
*/