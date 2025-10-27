#include "include/dns/fragment.h"
#include <isc/mem.h>
#include <isc/util.h>
#include <dns/fragment.h>
#include <dns/message.h>
#include <dns/types.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>

// key = id + client ip:port
static void fcache_create_key(dns_messageid_t id, char *client_address,unsigned client_address_size, unsigned char *key, unsigned keysize) {
    REQUIRE(keysize >= sizeof(id) + client_address_size);
    memcpy(key, &id, sizeof(id));
    memcpy(key + sizeof(id), &client_address, client_address_size);
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

// DNSKEY header: 2 (Flags) + 1 (Protocol) + 1 (Algorithm) = 4 Bytes
unsigned calc_dnskey_header_size() {
    return 4;
}

// RRSIG header: 2 (Type Covered) + 1 (Algorithm) + 1 (Labels) + 4 (TTL) + 4 (Expiration) + 4 (Inception) + 2 (Key Tag) + x (Signer Name) = 18 + x
unsigned calc_rrsig_header_size(dns_rdata_t *rdata) {
    int header_size = 18;  
    //signer's name length is variable
    while (rdata->data[header_size] != 0 && header_size < rdata->length) {
        header_size++;
    }
    return header_size;
}

unsigned calc_message_size(isc_mem_t *mctx, dns_message_t *msg,
    unsigned ***rr_sizes, unsigned *num_sig_rr, unsigned *num_dnskey_rr, 
    unsigned *total_sig_rr, unsigned *total_dnskey_rr, unsigned *savings) {

    *rr_sizes = isc_mem_get(mctx, DNS_SECTION_MAX * sizeof(unsigned *));

    unsigned rr_header_size = 10; // 2 (TYPE) + 2 (CLASS) + 4 (TTL) + 2 (RDLENGTH), excluding name
    unsigned msgsize = msg->buffer->used;
    // go through each section
    for(unsigned section = 0; section < DNS_SECTION_MAX; section++) {
        unsigned counter = 0;
        *rr_sizes[section] = isc_mem_get(mctx, msg->counts[section] * sizeof(unsigned));
        // go through each name, rdataset, and rdata item
        for (dns_name_t *name = ISC_LIST_HEAD(msg->sections[section]); name != NULL; ISC_LIST_NEXT(name, link)) {
            rr_header_size += name->length;
            for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                for (isc_result_t tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
				    dns_rdata_t rdata = DNS_RDATA_INIT;
                    dns_rdataset_current(rdataset, &rdata);
                    unsigned rdata_size = rdata.length;
                    *rr_sizes[section][counter] = rdata_size;
                    if (rdata.type == RRSIG) {
                        *num_sig_rr += 1;
                        *total_sig_rr += (rdata_size - calc_rrsig_header_size(&rdata)); // exclude RRSIG header
                    }
                    else if (rdata.type == DNSKEY) {
                        *num_dnskey_rr += 1;
                        *total_dnskey_rr += (rdata_size - calc_dnskey_header_size()); // exclude DNSKEY header
                    }
                    counter++;
                }
            }
        }
        REQUIRE(msg->counts[section] == counter); // sanity check: msg->counts[i] and counter should be the same after this
    }
    return msgsize;
}

unsigned estimate_message_size(dns_message_t *msg, unsigned *total_sig_bytes, unsigned *total_dnskey_bytes, unsigned *savings) {


    unsigned rr_header_size = 10; // 2 (TYPE) + 2 (CLASS) + 4 (TTL) + 2 (RDLENGTH), excluding name
    unsigned msgsize = 0;
    // go through each section
    for(unsigned i = 0; i < DNS_SECTION_MAX; i++) {
	    unsigned rr_count = msg->counts[i];
        unsigned counter = 0;
        // go through each name, rdataset, and rdata item
        for (dns_name_t *name = ISC_LIST_HEAD(msg->sections[i]); name != NULL; ISC_LIST_NEXT(name, link)) {
            rr_header_size += name->length;
            for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                for (isc_result_t tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
				    dns_rdata_t rdata = DNS_RDATA_INIT;
                    dns_rdataset_current(rdataset, &rdata);
                    unsigned rdata_size = rdata.size; // might be incorrect because it is a fragment
                    unsigned rr_size_frag = rdata_size + rr_header_size; // size of complete resource record
                    if (rdata.type == RRSIG) {
                        sig_size = get_alg_sig_pk_size(rdata);
                        rr_size = rr_size_frag - (rdata_size - calc_rrsig_header_size(&rdata)) + sig_size;
                        *num_sig_rr += 1;
                        *total_sig_bytes += sig_size;
                    }
                    else if (rdata.type == DNSKEY) {
                        pk_size = get_alg_sig_pk_size(rdata);
                        *num_dnskey_rr += 1;
                        *total_dnskey_bytes += (rdata_size - calc_dnskey_header_size()); // exclude DNSKEY header
                    }
                    else {
                        
                    }
                    counter++;
                }
            }
        }
        REQUIRE(rr_count == counter); // rr_count and counter should be the same after this
    }
    return msgsize;
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

//unsigned get_nr_fragments_2(const unsigned max_msg_size, const unsigned header_size, unsigned *can_send_first_msg, unsigned *can_send) {  
//}
 

bool fragment(isc_mem_t *mctx, dns_message_t *msg) {
    unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
    unsigned **rr_sizes; // contains the size of each resource record
    
    // calculate message size
    msgsize = calc_message_size(mctx, msg, &rr_sizes, &nr_sig_rr, &nr_dnskey_rr, &total_size_sig_rr, &total_size_dnskey_rr, &savings);
    // print information
    printf("total DNS Message size: %u\n", msgsize);
    printf("nr. sig: %d, total size: %d\n", nr_sig_rr, total_size_sig_rr);
    printf("nr. keys: %d, total size: %d\n", nr_dnskey_rr, total_size_dnskey_rr);
    unsigned total_sig_pk_bytes = total_size_sig_rr + total_size_dnskey_rr;
    unsigned rr_pk_sig_count = nr_sig_rr + nr_dnskey_rr;
    printf("total_sig_pk_bytes: %d\n", total_sig_pk_bytes);
    printf("MAXUDP: %d\n", MAXUDP);
    printf("savings: %d\n", savings);
    
    // calculate nr of fragments
    unsigned can_send_first_fragment, can_send;
    unsigned nr_fragments = get_nr_fragments(MAXUDP, msgsize, total_sig_pk_bytes, savings, &can_send_first_fragment, &can_send);
    printf("can_send (1st fragment): %u\n", can_send_first_fragment);
    printf("can_send (other fragments): %u\n", can_send);

    // 0-initialized array of offsets
    unsigned *offsets[DNS_SECTION_MAX];
    for(unsigned section = 0; section < DNS_SECTION_MAX; section++) {
        offsets[section] = isc_mem_get(mctx, msg->counts[section] * sizeof(unsigned));
    }

    if (nr_fragments == 1) {
        fprintf(stderr, "DNSMessage does not need UDP fragmentation!\n");
        return false;
    }

    // adding fragment to cache
    for (unsigned frag_nr = 0; frag_nr < nr_fragments; frag_nr++) {        
        printf("adding fragment %d to the fcache!\n", frag_nr);
        dns_message_t *frag;
        dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &frag);

        for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
            unsigned new_section_count = 0;
            for (dns_name_t *name = ISC_LIST_HEAD(msg->sections[section_nr]); name != NULL; ISC_LIST_NEXT(name, link)) {
                
                dns_name_t new_name;
                dns_name_init(&new_name, NULL);

                for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {

                    dns_rdataset_t new_rdataset;
                    dns_rdataset_init(&new_rdataset);

                    for (isc_result_t tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
                        dns_rdata_t rdata = DNS_RDATA_INIT;
                        dns_rdataset_current(rdataset, &rdata);

                        dns_rdata_t new_rdata;
                        dns_rdata_init(&new_rdata);
                        
                        if (rdata.type == DNSKEY || rdata.type == RRSIG) {
                            add_rr_fragment(frag, name, rdataset, rr, offsets[section_nr][rr_counter], fragment_length[section_nr][rr_counter]);
                            new_section_count++;
                        }
                        // 
                        else if (frag_nr == 0) {
                            add_rr(frag, name, rdataset, rr);
                            new_section_count++;
                        }
                        // already added in first fragment
                        else {
                            savings += rr.length; // do we need to include this? And is it with or without header?
                        }
                    }
                }
                dns_message_addname(dns_message_t *msg, dns_name_t *name, section_nr);
            }
            frag->counts[section_nr] = new_section_count;
        }
        printf("\nAdding Fragment %d to cache...\n", i);
        char *key = "createkeyhere";
        unsigned keysize;
        fcache_add(key, keysize, frag, nr_fragments);
    }
    
    // change first fragment so it fits in one packet

    return true;

}


// reassembles the complete message from cache
// assumption: cache contains all fragments
// assumption: size of fragments should add up to size specified in entry
static bool reassemble_fragments(isc_mem_t *mctx, fragment_cache_entry_t *entry, dns_message_t *out_msg) {
    REQUIRE(entry->bitmap == ~0);
    REQUIRE(out_msg == NULL);
    // copy first fragment
    isc_buffer_t *msg_buf;
    isc_buffer_dup(mctx, &msq_buf, entry->fragments[0]);
    dns_message_parse(out_msg, msg_buf, options); // create first fragment message

    for(unsigned frag_nr = 1; frag_nr < entry->nr_fragments; frag_nr++) {
        dns_message_t *frag;
        dns_message_parse(frag, entry->fragments[i], options);
        for(unsigned section = 0; section < DNS_SECTION_MAX; section++) {

            // loop through fragment resource records
            for (dns_name_t *name_f = ISC_LIST_HEAD(frag->sections[i]); name_f != NULL; ISC_LIST_NEXT(name_f, link)) {
                for (dns_rdataset_t *rdataset_f = ISC_LIST_HEAD(name_f->list); rdataset_f != NULL; rdataset_f = ISC_LIST_NEXT(rdataset_f, link)) {
                    for (isc_result_t tresult_f = dns_rdataset_first(rdataset_f); tresult_f == ISC_R_SUCCESS; tresult_f = dns_rdataset_next(rdataset_f)) {
                        dns_rdata_t rr_f = DNS_RDATA_INIT;
                        dns_rdataset_current(rdataset_f, &rr_f);

                        // find matching resource record in current message
                        for (dns_name_t *name = ISC_LIST_HEAD(msg->sections[i]); name != NULL; ISC_LIST_NEXT(name, link)) {
                            for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                                for (isc_result_t tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
                                    dns_rdata_t rr = DNS_RDATA_INIT;
                                    dns_rdataset_current(rdataset, &rr);
                                    // error prone: assumes message structure is the same for all
                                    // better is to check if it has the same qname/header
                                    if((rr->type == RRSIG && rr_f->type == RRSIG) || (rr->type == DNSKEY && rr_f->type == DNSKEY)) {
                                        combine(out_msg, frag); // combine and store in out msg
                                        goto next_rr;
                                    }
                                }
                            }
                        }
                        next_rr:
                    }
                }
            }


        }
    }
    // would be slightly more efficient to do this in the loop
    fcache_free_entry(entry);
}

// callback function for received fragments  dns_request_t *request, isc_result_t result, dns_message_t *response, 
static void frag_cb(void *arg) {
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
                // trigger original 
            }
        }
        else {
            printf("No entry for key %s in fragment cache!\n", key);
        }
    }
    else {
        printf("Request failed: %s\n", isc_result_totext(result));
    }
}


//This function is triggered on the first fragment it receives (resolver)
bool request_fragments(dns_request_t *query, dns_message_t *response) {
    REQUIRE(response.is_fragment && response.fragment_nr == 1); // should be the first fragment

    // estimate the number of fragments based on the amount of signature/pk bytes
    unsigned total_sig_bytes, total_dnskey_bytes, savings, can_send_first_msg, can_send;
    unsigned msg_size = estimate_message_size(response, &total_sig_bytes, &total_dnskey_bytes, &savings);
    unsigned total_sig_pk_bytes = total_sig_bytes + total_dnskey_bytes;
    unsigned nr_fragments = get_nr_fragments(MAXUDP, msg_size, total_sig_pk_bytes, savings, &can_send_first_msg, &can_send);

    printf("Adding first fragment to cache...\n");
    add_to_cache(dns_message_t *msg, dns_cache_t *cache);
    printf("Requesting %d additional fragments...\n", nr_fragments - 1);
    for (int i = 2; i <= nr_fragments; i++) {
        dns_request_t *request = NULL;
        dns_message_t request_msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &request_msg);
        

        result = dns_request_create(query->requestmgr, request_msg,
		   const isc_sockaddr_t *srcaddr, query->destaddr, dns_transport_t *transport,
		   isc_tlsctx_cache_t *tlsctx_cache, unsigned int options,
		   dns_tsigkey_t *key, unsigned int timeout,
		   unsigned int udptimeout, unsigned int udpretries,
		   isc_loop_t *loop, frag_cb, message, 
           &request); 
        REQUIRE(result == ISC_R_SUCCESS); // request is created succesfully

        // Send the request
        result = dns_request_send(&request);
        REQUIRE(result == ISC_R_SUCCESS); // request is sent succesfuully
    }
}
