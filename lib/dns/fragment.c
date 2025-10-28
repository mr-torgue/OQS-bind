#include "include/dns/fragment.h"
#include <isc/buffer.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/types.h>
#include <isc/util.h>
#include <dns/fragment.h>
#include <dns/message.h>
#include <dns/rdatalist.h>
#include <dns/types.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>


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
                    unsigned rdata_length = rdata.length; // might be incorrect because it is a fragment
                    unsigned rr_size_frag = rdata_length + rr_header_size; // size of complete resource record
                    unsigned rr_size;
                    if (rdata.type == RRSIG) {
                        unsigned sig_size = get_alg_sig_size(rdata.data[2]);
                        rr_size = rr_size_frag - (rdata_length - calc_rrsig_header_size(&rdata)) + sig_size;
                        *total_sig_bytes += sig_size;
                    }
                    else if (rdata.type == DNSKEY) {
                        unsigned pk_size = get_alg_pk_size(rdata.data[3]);
                        rr_size = rr_size_frag - (rdata_length - calc_dnskey_header_size()) + pk_size;
                        *total_dnskey_bytes += pk_size;
                    }
                    else {
                        rr_size = rr_size_frag; // only DNSKEY and RRSIG get fragmented -> full message
                    }
                    msgsize += rr_size;
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

static void add_rdata_to_name(dns_message_t *msg, dns_name_t *name, dns_rdata_t *rdata,
		  uint32_t ttl, dns_namelist_t *namelist, unsigned start, unsigned end) {
	isc_region_t r, newr;
	dns_rdata_t *newrdata = NULL;
	dns_name_t *newname = NULL;
	dns_rdatalist_t *newlist = NULL;
	dns_rdataset_t *newset = NULL;
	isc_buffer_t *tmprdatabuf = NULL;
    unsigned new_rdata_length = end - start;

	dns_message_gettemprdata(msg, &newrdata);

	dns_rdata_toregion(rdata, &r);
	isc_buffer_allocate(msg->mctx, &tmprdatabuf, new_rdata_length);
	isc_buffer_availableregion(tmprdatabuf, &newr);
	memmove(newr.base, r.base + start, new_rdata_length);
	dns_rdata_fromregion(newrdata, rdata->rdclass, rdata->type, &newr);
	dns_message_takebuffer(msg, &tmprdatabuf);

	dns_message_gettempname(msg, &newname);
	dns_name_copy(name, newname);

	dns_message_gettemprdatalist(msg, &newlist);
	newlist->rdclass = newrdata->rdclass;
	newlist->type = newrdata->type;
	newlist->ttl = ttl;
	ISC_LIST_APPEND(newlist->rdata, newrdata, link);

	dns_message_gettemprdataset(msg, &newset);
	dns_rdatalist_tordataset(newlist, newset);

	ISC_LIST_INIT(newname->list);
	ISC_LIST_APPEND(newname->list, newset, link);

	ISC_LIST_APPEND(*namelist, newname, link);
}

static void calculate_start_end(unsigned fragment_nr, unsigned nr_fragments, unsigned offset, unsigned rdata_size, unsigned can_send_first_fragment, unsigned can_send, unsigned total_pk_sig_bytes_per_frag, unsigned rr_pk_sig_count, unsigned *start, unsigned *frag_len) {
    REQUIRE(offset < rdata_size);
    unsigned rem_space_per_frag, can_send_additional, rem_space_per_frag_1, can_send_additional_1;                            
    unsigned num_bytes_to_send = rdata_size / nr_fragments;
    rem_space_per_frag_1 = can_send_first_fragment - total_pk_sig_bytes_per_frag; 
    rem_space_per_frag = can_send - total_pk_sig_bytes_per_frag;
    can_send_additional_1 = rem_space_per_frag_1 / rr_pk_sig_count;
    can_send_additional = rem_space_per_frag / rr_pk_sig_count;
    printf("rem_space_per_frag_1: %d\n", rem_space_per_frag_1);
    printf("can_send_additional_1: %d\n", can_send_additional_1);
    printf("rem_space_per_frag: %d\n", rem_space_per_frag);
    printf("can_send_additional: %d\n", can_send_additional);
    *start = offset;
    // first fragment
    if (offset == 0) {
        *frag_len = num_bytes_to_send + can_send_additional_1;
    }
    else {
        *frag_len = num_bytes_to_send + can_send_additional;
    }   

    if (fragment_nr == nr_fragments - 1 || *start + *frag_len > rdata_size) {
        *frag_len = rdata_size - *start;
    }
    REQUIRE(fragment_nr != nr_fragments - 1 || *frag_len + *start == rdata_size);
}
 
bool fragment(isc_mem_t *mctx, dns_message_t *msg, char *client_address, unsigned client_address_size) {
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

    unsigned num_sig_bytes_per_frag = total_size_sig_rr / nr_fragments;
    printf("num_sig_bytes_per_frag: %d\n", num_sig_bytes_per_frag);
    unsigned num_pk_bytes_per_frag = total_size_dnskey_rr / nr_fragments;
    printf("num_pk_bytes_per_frag: %d\n", num_pk_bytes_per_frag);
    unsigned total_sig_pk_bytes_per_frag = num_sig_bytes_per_frag + num_pk_bytes_per_frag;

    if (nr_fragments == 1) {
        fprintf(stderr, "DNSMessage does not need UDP fragmentation!\n");
        return false;
    }

    // 0-initialized array of offsets
    unsigned **offsets = isc_mem_get(mctx, DNS_SECTION_MAX * sizeof(unsigned *));
    for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
        offsets[section_nr] = isc_mem_get(mctx, msg->counts[section_nr] * sizeof(unsigned));
    }


    // adding fragment to cache
    for (unsigned frag_nr = 0; frag_nr < nr_fragments; frag_nr++) {        
        printf("adding fragment %d to the fcache!\n", frag_nr);
        dns_message_t *frag;
        dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &frag);
    
        for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
            unsigned new_section_count = 0;
            unsigned counter = 0;

            for (dns_name_t *name = ISC_LIST_HEAD(msg->sections[section_nr]); name != NULL; ISC_LIST_NEXT(name, link)) {
                
                dns_name_t new_name;
                dns_name_init(&new_name, NULL);
                ISC_LIST_INIT(new_name.list);

                for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {

                    dns_rdataset_t new_rdataset;
                    dns_rdataset_init(&new_rdataset);
                    dns_rdatalist_t rdatalist;

                    for (isc_result_t tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
                        dns_rdata_t rdata = DNS_RDATA_INIT;
                        dns_rdataset_current(rdataset, &rdata);

                        dns_rdata_t new_rdata;
                        dns_rdata_clone(&rdata, &new_rdata);
                        
                        if (rdata.type == DNSKEY || rdata.type == RRSIG) {
                            unsigned new_rdata_start, new_rdata_length;
                            // get start and length
                            calculate_start_end(frag_nr, nr_fragments, offsets[section_nr][counter], rr_sizes[section_nr][counter], can_send_first_fragment, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, &new_rdata_start, &new_rdata_length);


	                        unsigned char *new_data = isc_mem_get(mctx, new_rdata_length * sizeof(unsigned char));
                            memcpy(new_data, rdata.data + new_rdata_start, new_rdata_length);
                            new_rdata.data = new_data;
                            new_rdata.length = new_rdata_length;
                            ISC_LIST_APPEND(rdatalist.rdata, &new_rdata, link);
                            new_section_count++;
                            offsets[section_nr][counter] = new_rdata_start;
                        }
                        else if (frag_nr == 0) {
                            unsigned char *new_data = isc_mem_get(mctx, rdata.length * sizeof(unsigned char));
                            memcpy(new_data, rdata.data, rdata.length);
                            new_rdata.data = new_data;
                            ISC_LIST_APPEND(rdatalist.rdata, &new_rdata, link);
                            new_section_count++;
                        }
                        // already added in first fragment
                        else {
                            savings += rdata.length; // do we need to include this? And is it with or without header?
                        }
                        counter++;
                        // convert to rdataset and link to new name
                        dns_rdatalist_tordataset(&rdatalist, &new_rdataset);
                        ISC_LIST_APPEND(new_name.list, &new_rdataset, link);
                    }
                } 
                // check if not empty??
                dns_message_addname(frag, &new_name, section_nr);
            }
            REQUIRE(counter == msg->counts[section_nr]); 
            frag->counts[section_nr] = new_section_count;
        }
        printf("Adding Fragment %d to cache...\n", frag_nr);
        unsigned keysize = sizeof(dns_messageid_t) + client_address_size;
        unsigned char *key = isc_mem_get(mctx, keysize);
        fcache_create_key(msg->id, client_address, client_address_size, key, keysize);
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
    isc_buffer_dup(mctx, &msg_buf, entry->fragments[0]);
    dns_message_parse(out_msg, msg_buf, 0); // create first fragment message

    for(unsigned frag_nr = 1; frag_nr < entry->nr_fragments; frag_nr++) {
        dns_message_t *frag;
        dns_message_parse(frag, entry->fragments[frag_nr], 0);
        for(unsigned section = 0; section < DNS_SECTION_MAX; section++) {

            // loop through fragment resource records
            for (dns_name_t *name_f = ISC_LIST_HEAD(frag->sections[i]); name_f != NULL; ISC_LIST_NEXT(name_f, link)) {
                for (dns_rdataset_t *rdataset_f = ISC_LIST_HEAD(name_f->list); rdataset_f != NULL; rdataset_f = ISC_LIST_NEXT(rdataset_f, link)) {
                    for (isc_result_t tresult_f = dns_rdataset_first(rdataset_f); tresult_f == ISC_R_SUCCESS; tresult_f = dns_rdataset_next(rdataset_f)) {
                        dns_rdata_t rr_f = DNS_RDATA_INIT;
                        dns_rdataset_current(rdataset_f, &rr_f);

                        // find matching resource record in current message
                        for (dns_name_t *name = ISC_LIST_HEAD(frag->sections[i]); name != NULL; ISC_LIST_NEXT(name, link)) {
                            for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                                for (isc_result_t tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
                                    dns_rdata_t rr = DNS_RDATA_INIT;
                                    dns_rdataset_current(rdataset, &rr);
                                    // error prone: assumes message structure is the same for all
                                    // better is to check if it has the same qname/header
                                    if((rr.type == RRSIG && rr_f.type == RRSIG) || (rr.type == DNSKEY && rr_f.type == DNSKEY)) {
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
        dns_dispatch_send(request->dispentry);
        REQUIRE(result == ISC_R_SUCCESS); // request is sent succesfuully
    }
}
