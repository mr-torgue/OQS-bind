#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <isc/buffer.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>
#include <dns/compress.h>
#include <dns/enumtype.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdatalist.h>
#include <dns/types.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/qbf.h>



// Note: calculates the maximum message size, so names are assumed to not be compressed
// only support for question section with one question
unsigned calc_message_size(dns_message_t *msg,
    unsigned *num_sig_rr, unsigned *num_dnskey_rr, 
    unsigned *total_sig_rr, unsigned *total_dnskey_rr, unsigned *savings, unsigned *counts, const unsigned count_size) {
    REQUIRE(msg != NULL);
    REQUIRE(msg->mctx != NULL);
    REQUIRE(counts != NULL && count_size == DNS_SECTION_MAX);
    // initalize values
    *num_sig_rr = 0;
    *num_dnskey_rr = 0;
    *total_sig_rr = 0;
    *total_dnskey_rr = 0;
    *savings = 0;

    
    dns_name_t *name = NULL;
    dns_rdataset_t *rdataset = NULL;
    unsigned msgsize = 12; // ID (2B) + Flags (2B) + Counts (4x2B)

    // count question
    isc_result_t result = dns_message_firstname(msg, DNS_SECTION_QUESTION);
    REQUIRE(result == ISC_R_SUCCESS);
    dns_message_currentname(msg, DNS_SECTION_QUESTION, &name);
    msgsize += name->length + 4; // 4: type (2B) + class (2B)
    counts[DNS_SECTION_QUESTION] = 1; 


    // we already have the total size, now we determine the amount of dnskeys/signatures
    // skip question section
    for(unsigned section = 1; section < DNS_SECTION_MAX; section++) {
        // go through each name, rdataset, and rdata item
        for (isc_result_t nresult = dns_message_firstname(msg, section); nresult == ISC_R_SUCCESS;  nresult = dns_message_nextname(msg, section)) {
            name = NULL;
            dns_message_currentname(msg, section, &name);
            unsigned rr_header_size = 10; // 2 (TYPE) + 2 (CLASS) + 4 (TTL) + 2 (RDLENGTH), excluding name
            // usually names are compressed
            if (name->attributes.nocompress) { 
                rr_header_size += name->length;
            }
            else if (name->length == 1) { // for root
                rr_header_size++;
            }
            else {
                rr_header_size += 2;
            }
            
            for (rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                isc_result_t tresult;
                for (tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
                    dns_rdata_t rdata = DNS_RDATA_INIT;
                    dns_rdataset_current(rdataset, &rdata);
                    unsigned rdata_size = rdata.length;
                    //printf("rdata.length: %u, rdata.wirelength: %u\n", rdata.length, rdata.wirelength);
                    // TODO: enable as soon as we don't change the qname anymore
                    if (rdata.wirelength != 0) {
                        rdata_size = rdata.wirelength;
                    }
                    if (rdata.type == RRSIG) {
                        *num_sig_rr += 1;
                        *total_sig_rr += (rdata_size - calc_rrsig_header_size(&rdata)); // exclude RRSIG header
                    }
                    else if (rdata.type == DNSKEY) {
                        *num_dnskey_rr += 1;
                        *total_dnskey_rr += (rdata_size - calc_dnskey_header_size()); // exclude DNSKEY header
                    }
                    else {
                        *savings += rr_header_size + rdata_size;
                    }
                    msgsize += rr_header_size + rdata_size;
                    counts[section]++; 
                }
            }
        }
    }
    // OPT record found!
    // only one allowed and can only be in the additional section
    if (msg->opt != NULL) {
        REQUIRE(dns_rdataset_count(msg->opt) == 1);
        msgsize += 11; // OPT header size
        isc_result_t tresult;
        // iterate through this (i think there only should be one)
        for (tresult = dns_rdataset_first(msg->opt); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(msg->opt)) {
            dns_rdata_t rdata = DNS_RDATA_INIT;
            dns_rdataset_current(msg->opt, &rdata);
            msgsize += rdata.length;
        }
        counts[DNS_SECTION_ADDITIONAL]++; 
    }
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
        "Calculated message size %u for message %u with %u bytes of DNSKEY and %u bytes of RRSIG", msgsize, msg->id, *total_dnskey_rr, *total_sig_rr); 
    return msgsize;
}

unsigned estimate_message_size(dns_message_t *msg, unsigned *total_sig_bytes, unsigned *total_dnskey_bytes, unsigned *savings) {
    REQUIRE(msg != NULL);
    // initialize return values
    *total_sig_bytes = 0;
    *total_dnskey_bytes = 0;
    *savings = 0;

    dns_name_t *name = NULL;
    dns_rdataset_t *rdataset = NULL;

    unsigned msgsize = 12; // ID (2B) + Flags (2B) + Counts (4x2B)

    // count question
    isc_result_t result = dns_message_firstname(msg, DNS_SECTION_QUESTION);
    REQUIRE(result == ISC_R_SUCCESS);
    dns_message_currentname(msg, DNS_SECTION_QUESTION, &name);
    msgsize += name->length + 4; // 4: type (2B) + class (2B)
    
    // go through each section
    for(unsigned section = 1; section < DNS_SECTION_MAX; section++) {
        unsigned counter = 0;
        // go through each name, rdataset, and rdata item
        for (result = dns_message_firstname(msg, section); result == ISC_R_SUCCESS;  result = dns_message_nextname(msg, section)) {
            name = NULL;
            dns_message_currentname(msg, section, &name);
            unsigned rr_header_size = 10; // 2 (TYPE) + 2 (CLASS) + 4 (TTL) + 2 (RDLENGTH), excluding name
            // usually names are compressed
            if (name->attributes.nocompress) { 
                rr_header_size += name->length;
            }
            else if (name->length == 1) { // for root
                rr_header_size++;
            }
            else {
                rr_header_size += 2;
            }
            for (rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                isc_result_t tresult;
                for (tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
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
                        *savings += rr_size;
                    }
                    msgsize += rr_size;
                    counter++;
                }
            }
        }
        // can be moved outside of this loop 
        // OPT record found!
        // only one allowed and can only be in the additional section
        if (msg->opt != NULL && section == DNS_SECTION_ADDITIONAL) {
            REQUIRE(dns_rdataset_count(msg->opt) == 1);
            msgsize += 11; // OPT header size
            isc_result_t tresult;
            // iterate through this (i think there only should be one)
            for (tresult = dns_rdataset_first(msg->opt); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(msg->opt)) {
                dns_rdata_t rdata = DNS_RDATA_INIT;
                dns_rdataset_current(msg->opt, &rdata);
                msgsize += rdata.length;
            }

            counter++;
        }
        REQUIRE(msg->counts[section] == counter); // rr_count and counter should be the same after this
    }
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
        "Estimated message size %u for message %u with %u bytes of DNSKEY and %u bytes of RRSIG", msgsize, msg->id, *total_dnskey_bytes, *total_sig_bytes); 
    return msgsize;
}


unsigned get_nr_fragments(const unsigned max_msg_size, const unsigned total_msg_size, const unsigned total_sig_pk_bytes, const unsigned savings, const unsigned overhead, unsigned *can_send_first_msg, unsigned *can_send) {
    REQUIRE(total_msg_size > total_sig_pk_bytes); 
    REQUIRE(overhead == 6 || overhead == 17); // should be 6 if there already was an OPT record, or 17 if new one has been created
    unsigned num_fixed_bytes = total_msg_size - total_sig_pk_bytes;
    REQUIRE(max_msg_size > num_fixed_bytes); // fixed bytes should fit in a message
    *can_send = max_msg_size - num_fixed_bytes - overhead;
    *can_send_first_msg = *can_send;
    unsigned nr_fragments = 0;

    unsigned counter = 0;
    while (total_sig_pk_bytes > counter) {
        counter += *can_send;
        if (nr_fragments == 0) {
            *can_send += savings;
        }
        nr_fragments++;
        REQUIRE(nr_fragments < 100); // just to make sure qname_overhead is correct
    }
    // we always need at least one fragment
    if (total_sig_pk_bytes == 0) {
        nr_fragments++;
    }
    // check that the can send never exceeds max_msg_size
    REQUIRE(num_fixed_bytes + *can_send_first_msg <= max_msg_size);
    REQUIRE(num_fixed_bytes - savings + *can_send <= max_msg_size);
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Message with size %u needs %u fragments (max size: %u, pk-sig bytes: %u)", total_msg_size, nr_fragments, max_msg_size, total_sig_pk_bytes);  
    return nr_fragments;
}




void calculate_start_end(unsigned fragment_nr, unsigned nr_fragments, unsigned offset, unsigned rdata_size, unsigned can_send_first_fragment, unsigned can_send, unsigned total_pk_sig_bytes, unsigned *start, unsigned *frag_len, double *remainder, unsigned *used_bytes) {
    REQUIRE(offset < rdata_size);                       
    double num_bytes_to_send, tmp;
    //unsigned num_bytes_to_send_i;
    // should make sure that it spreads evenly according to 
    *start = offset;

    // first fragment
    if (offset == 0) {
        // calculate the fraction and spend that much based on how much you can send
        num_bytes_to_send = ((double)rdata_size / total_pk_sig_bytes) * can_send_first_fragment;
        *frag_len = num_bytes_to_send;
    }
    else {
        // calculate the fraction and spend that much based on how much you can send
        num_bytes_to_send = ((double)rdata_size / total_pk_sig_bytes) * can_send;
        *frag_len = num_bytes_to_send;
    }
    
    *remainder += modf(num_bytes_to_send, &tmp);
    //printf("num_bytes_to_send: %u\n", (unsigned)num_bytes_to_send);
    // make sure it never exceeds the limit
    if (fragment_nr == nr_fragments - 1 || *start + *frag_len >= rdata_size) {
        *frag_len = rdata_size - *start;
    }
    // check remainder to add another byte if possible
    // idea: we could have send 0.x (remainder) more bytes but did not
    //       once we accumalate more than 1 bytes, we can increase by 1
    else if (*remainder >= 1) {
        (*frag_len)++;
        (*remainder)--;
    }

    *used_bytes += *frag_len;
    if (fragment_nr == 0) {
        REQUIRE(*used_bytes <= can_send_first_fragment);
    }
    else {
        REQUIRE(*used_bytes <= can_send);
    }
    //printf("*frag_len: %u\n", *frag_len);
    
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Fragment %u split into [%u, %u)], max size: %u", fragment_nr, *start, *start + *frag_len, rdata_size);  
    REQUIRE(fragment_nr != nr_fragments - 1 || *frag_len + *start == rdata_size);
}
 
// todo, reduce size
isc_result_t fragment(isc_mem_t *mctx, fcache_t *fcache, dns_message_t *msg, char *client_address, const unsigned max_udp_size) {
    REQUIRE(msg != NULL);
    REQUIRE(mctx != NULL);
    //msg->flags |= DNS_MESSAGEFLAG_TC; // quick fix: somehow the flag is not always set
    //REQUIRE(msg->flags & DNS_MESSAGEFLAG_TC); // truncated flag should be set
    unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
    // calculate message size
    unsigned counts[DNS_SECTION_MAX] = {0};
    msgsize = calc_message_size(msg, &nr_sig_rr, &nr_dnskey_rr, &total_size_sig_rr, &total_size_dnskey_rr, &savings, counts, DNS_SECTION_MAX);
    if (msg->counts[0] != 0) {
        REQUIRE(msg->counts[0] == counts[0]);
    }
    if (msg->counts[1] != 0) {
        REQUIRE(msg->counts[1] == counts[1]);
    }
    if (msg->counts[2] != 0) {
        REQUIRE(msg->counts[2] == counts[2]);
    }
    if (msg->counts[3] != 0) {
        REQUIRE(msg->counts[3] == counts[3]);
    }
    // print information
    unsigned total_sig_pk_bytes = total_size_sig_rr + total_size_dnskey_rr;
    //unsigned rr_pk_sig_count = nr_sig_rr + nr_dnskey_rr;
    
    // calculate nr of fragments
    unsigned can_send_first_fragment, can_send_other_fragments;
    unsigned overhead = msg->opt == NULL ? 17 : 6;
    unsigned nr_fragments = get_nr_fragments(max_udp_size, msgsize, total_sig_pk_bytes, savings, overhead, &can_send_first_fragment, &can_send_other_fragments);

    unsigned total_bytes_to_send = savings + total_sig_pk_bytes; // only RR in savings and total_sig_pk_bytes need to be sent
    //unsigned num_bytes_per_frag = total_bytes_to_send / nr_fragments;


    unsigned num_sig_bytes_per_frag = total_size_sig_rr / nr_fragments;
    unsigned num_pk_bytes_per_frag = total_size_dnskey_rr / nr_fragments;
    //unsigned total_sig_pk_bytes_per_frag = num_sig_bytes_per_frag + num_pk_bytes_per_frag;

    if (nr_fragments == 1) { 
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "DNSMessage does not need UDP fragmentation!");  
        return ISC_R_RANGE;
    }

    // 0-initialized array of offsets
    unsigned **offsets = isc_mem_get(mctx, DNS_SECTION_MAX * sizeof(unsigned *));
    for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
        offsets[section_nr] = isc_mem_get(mctx, counts[section_nr] * sizeof(unsigned));
        memset(offsets[section_nr], 0, counts[section_nr] * sizeof(unsigned));
    }
    
    // create cache key
    unsigned char key[69];
    unsigned keysize = sizeof(key) / sizeof(key[0]);
    fcache_create_key(msg->id, client_address, key, &keysize);

    dns_name_t *name = NULL;
    isc_result_t fcache_res = fcache_add(fcache, key, keysize, nr_fragments);
    if (fcache_res == ISC_R_EXISTS) {
        // free memory
        for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
            isc_mem_put(mctx, offsets[section_nr], counts[section_nr] * sizeof(unsigned));
        }
        isc_mem_put(mctx, offsets, DNS_SECTION_MAX * sizeof(unsigned *));
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Cannot fragment response because it is already fragmented!");  
        return ISC_R_EXISTS;        
    }
    // adding fragment to cache
    for (unsigned frag_nr = 0; frag_nr < nr_fragments; frag_nr++) {        
        dns_message_t *frag = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &frag);
        double remainder = 0;
        unsigned used_bytes = 0;

        // set metadata
        frag->id = msg->id;
        frag->flags = msg->flags;
        frag->rcode = msg->rcode;
        frag->opcode = msg->opcode;
        frag->rdclass = msg->rdclass;
        // set fragmentation metadata
        frag->is_fragment = true;
        frag->fragment_nr = frag_nr;
        
        // go through remaining sections
        for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
            unsigned new_section_count = 0;
            unsigned counter = 0;

            // ignore if there are no resource records
            if(counts[section_nr] > 0) {
                for (isc_result_t result = dns_message_firstname(msg, section_nr); result == ISC_R_SUCCESS;  result = dns_message_nextname(msg, section_nr)) {
                    name = NULL;
                    dns_message_currentname(msg, section_nr, &name);
                    dns_name_t *new_name = NULL;
                    dns_message_gettempname(frag, &new_name);
                    dns_name_copy(name, new_name);

                    for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {

                        dns_rdataset_t *new_rdataset = NULL;
                        dns_message_gettemprdataset(frag, &new_rdataset);
                        dns_rdatalist_t *rdatalist = NULL;
                        dns_message_gettemprdatalist(frag, &rdatalist);

                        // copy values
                        rdatalist->rdclass = rdataset->rdclass;
                        rdatalist->type = rdataset->type;
                        rdatalist->ttl = rdataset->ttl;

                        for (isc_result_t tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
                            // get current rdata
                            dns_rdata_t rdata = DNS_RDATA_INIT;
                            dns_rdataset_current(rdataset, &rdata);
                            isc_region_t rdata_region;
		                    dns_rdata_toregion(&rdata, &rdata_region);

                            // prepare new rdata
                            dns_rdata_t *new_rdata = NULL;
                            dns_message_gettemprdata(frag, &new_rdata);
                            isc_region_t new_rdata_region;
                            /**/
                            // NOTE: each rdataset should only contain one type of record
                            if (rdata.type == DNSKEY || rdata.type == RRSIG) {
                                unsigned header_size = 0;
                                if(rdata.type == DNSKEY) {
                                    header_size = calc_dnskey_header_size();
                                }
                                // RRSIG
                                else {
                                    header_size = calc_rrsig_header_size(&rdata);
                                }
                                unsigned rdsize_no_header = rdata.length - header_size; 
                                unsigned new_rdata_start, new_rdata_length;
                                // check if there is data left
                                // edge case: some rr's get sent in n-1 fragments instead of n
                                if (offsets[section_nr][counter] < rdsize_no_header) {
                                    // get start and length
                                    calculate_start_end(frag_nr, nr_fragments, offsets[section_nr][counter], rdsize_no_header, can_send_first_fragment, can_send_other_fragments, total_sig_pk_bytes, &new_rdata_start, &new_rdata_length, &remainder, &used_bytes);
                                    REQUIRE(new_rdata_start + new_rdata_length <= rdsize_no_header);
                                    isc_buffer_t *buf = NULL;
                                    isc_buffer_allocate(mctx, &buf, new_rdata_length + header_size); // allocate
                                    isc_buffer_putmem(buf, rdata_region.base, header_size); // copy rdata header
                                    isc_buffer_putmem(buf, rdata_region.base + header_size + new_rdata_start, new_rdata_length); // copy rdata data
                                    isc_buffer_usedregion(buf, &new_rdata_region); 
                                    dns_rdata_fromregion(new_rdata, rdata.rdclass, rdata.type, &new_rdata_region); // create new rdata
                                    REQUIRE(new_rdata_region.length == new_rdata_length + header_size);
                                    dns_message_takebuffer(msg, &buf);
                                    ISC_LIST_APPEND(rdatalist->rdata, new_rdata, link); // append to list
                                    new_section_count++;
                                    offsets[section_nr][counter] = new_rdata_start + new_rdata_length;
                                }
                            }
                            else if (frag_nr == 0) {
                                isc_buffer_t *buf = NULL;
                                isc_buffer_allocate(mctx, &buf, rdata_region.length); // allocate
                                isc_buffer_putmem(buf, rdata_region.base, rdata_region.length); // copy rdata
                                isc_buffer_usedregion(buf, &new_rdata_region); 
                                dns_rdata_fromregion(new_rdata, rdata.rdclass, rdata.type, &new_rdata_region); // create new rdata
                                REQUIRE(new_rdata_region.length == rdata_region.length);
                                dns_message_takebuffer(msg, &buf);
                                ISC_LIST_APPEND(rdatalist->rdata, new_rdata, link);
                                new_section_count++;
                            }
                            counter++;
                        }
                        // convert to rdataset and link to new name
                        dns_rdatalist_tordataset(rdatalist, new_rdataset);
                        new_rdataset->attributes = rdataset->attributes; 
                        new_rdataset->attributes &= ~DNS_RDATASETATTR_RENDERED; // reset this flag to render
                        ISC_LIST_APPEND(new_name->list, new_rdataset, link);
                        REQUIRE(DNS_RDATASET_VALID(new_rdataset));
                    } 
                    if (section_nr == DNS_SECTION_QUESTION) {
                        counter++;
                        new_section_count = 1; // should always be one
                        REQUIRE(counts[DNS_SECTION_QUESTION == 1]); // too strict?
                    }
                    dns_message_addname(frag, new_name, section_nr);
                }
            }
            // can be moved, but leads to sanity check issues
            // only one allowed and can only be in the additional section
            if (section_nr == DNS_SECTION_ADDITIONAL) {
                create_fragment_opt(frag, frag_nr, nr_fragments, 0); // just set the flags to 0 for now
                new_section_count++;
                counter++;
            }

            REQUIRE(counter == counts[section_nr]); 
            frag->counts[section_nr] = new_section_count;
        }
	    REQUIRE(DNS_MESSAGE_VALID(frag));
        isc_result_t render_result = render_fragment(mctx, 1500, &frag); 
        REQUIRE(frag->buffer->used <= 1232);
        if (render_result != ISC_R_SUCCESS) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Failed to render the fragment!");  
            return render_result;
        }
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Adding fragment %u of length %u for message %u to cache...", frag_nr, frag->buffer->used, frag->id);  
        fcache_res = fcache_add_fragment(fcache, key, keysize, frag);
        if (fcache_res != ISC_R_SUCCESS) { 
            // free memory
            for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
                isc_mem_put(mctx, offsets[section_nr], counts[section_nr] * sizeof(unsigned));
            }
            isc_mem_put(mctx, offsets, DNS_SECTION_MAX * sizeof(unsigned *));
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Could not add fragment to cache...");
            return fcache_res;
        }
        dns_message_detach(&frag);
    }
    
    // free memory
    for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
        isc_mem_put(mctx, offsets[section_nr], counts[section_nr] * sizeof(unsigned));
    }
    isc_mem_put(mctx, offsets, DNS_SECTION_MAX * sizeof(unsigned *));

    return ISC_R_SUCCESS;

}

// reassembles the complete message from cache
// assumption: cache contains all fragments
// assumption: size of fragments should add up to size specified in entry
isc_result_t reassemble_fragments(isc_mem_t *mctx, fcache_t *fcache, unsigned char *key, unsigned keysize, dns_message_t **out_msg) {
    REQUIRE(out_msg != NULL && *out_msg == NULL);

    // try to find cache entry
    fragment_cache_entry_t *entry = NULL;
    isc_result_t result = fcache_get(fcache, key, keysize, &entry);
    if (result != ISC_R_SUCCESS) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Could not get fragment entry from cache!");  
        return result;
    }

    // check if all fragments are in cache
    if (entry->bitmap != (1u << entry->nr_fragments) - 1) {    
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Not all fragments have been received for entry %s (bitmap: %lx)", entry->key, entry->bitmap);  
        return ISC_R_INPROGRESS;
    }

    // create new message
    //dns_message_t *tmp_msg = NULL;
    dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, out_msg);

    // copy first fragment
    isc_buffer_t *frag_buf = NULL;
    fcache_get_fragment_from_entry(fcache, entry, 0, &frag_buf);
    result = dns_message_parse(*out_msg, frag_buf, DNS_MESSAGEPARSE_PRESERVEORDER); // create first fragment message
    if (result != ISC_R_SUCCESS) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Could not parse fragment!");  
        dns_message_detach(out_msg);
        return result;
    }
    dns_messageid_t id = (*out_msg)->id;

    // first fragment is already copied
    for(unsigned frag_nr = 1; frag_nr < entry->nr_fragments; frag_nr++) {
        dns_message_t *frag = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &frag);
        frag_buf = NULL;
        fcache_get_fragment_from_entry(fcache, entry, frag_nr, &frag_buf);
        result = dns_message_parse(frag, frag_buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        if (result != ISC_R_SUCCESS) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Could not parse fragment!");  
            dns_message_detach(out_msg);
            return result;
        }
        // check if the fragments in fcache belong to the same message
        if (id != frag->id) {
            isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Fragments have a mismatching ID: %u and %u", id, frag->id);  
            dns_message_detach(&frag);
            dns_message_detach(out_msg);
            return ISC_R_FAILURE;            
        }

        // we build a new message everytime
        //dns_message_t *builder = NULL;
        //dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &builder);

        for(unsigned section = 1; section < DNS_SECTION_MAX; section++) {
            // set msg pointer to first name, first rrset, first rr
            // I think this should always work...
            isc_result_t result_msg = dns_message_firstname(*out_msg, section);
            
            // possible. for example OPT record is not stored in the main dns message structure
            if(frag->counts[section] > 0 && result_msg == ISC_R_SUCCESS) {
                dns_name_t *name_msg = NULL;
                dns_message_currentname(*out_msg, section, &name_msg);
                dns_rdataset_t *rdataset_msg = ISC_LIST_HEAD(name_msg->list);
                //REQUIRE(rdataset_msg != NULL);
                isc_result_t tresult_msg = dns_rdataset_first(rdataset_msg); 

                // by definition, all records in later fragments must be in earlier fragments
                // so, we start with the fragment and keep iterating until we find the corresponding rr in the earlier fragment
                // loop through fragment resource records
                for (isc_result_t result_frag = dns_message_firstname(frag, section); result_frag == ISC_R_SUCCESS;  result_frag = dns_message_nextname(frag, section)) {
                    dns_name_t *name_frag = NULL;
                    dns_message_currentname(frag, section, &name_frag);

                    for (dns_rdataset_t *rdataset_frag = ISC_LIST_HEAD(name_frag->list); rdataset_frag != NULL; rdataset_frag = ISC_LIST_NEXT(rdataset_frag, link)) {
                        for (isc_result_t tresult_frag = dns_rdataset_first(rdataset_frag); tresult_frag == ISC_R_SUCCESS; tresult_frag = dns_rdataset_next(rdataset_frag)) {
                            dns_rdata_t rdata_frag = DNS_RDATA_INIT;
                            dns_rdataset_current(rdataset_frag, &rdata_frag);

                            // find matching resource record in the message
                            while (result_msg == ISC_R_SUCCESS) {
                                while (rdataset_msg != NULL) {
                                    while(tresult_msg == ISC_R_SUCCESS) {
                                        //dns_rdata_t rdata = DNS_RDATA_INIT;
                                        //dns_rdataset_current(rdataset, &rdata);

                                        dns_rdata_t *rdata_msg = rdataset_msg->rdlist.iter; // pointer not copy, we need to change the values inside
                                        tresult_msg = dns_rdataset_next(rdataset_msg);

                                        // error prone: assumes message structure is the same for all
                                        // better is to check if it has the same qname/header
                                        if((rdata_msg->type == RRSIG && rdata_frag.type == RRSIG) || (rdata_msg->type == DNSKEY && rdata_frag.type == DNSKEY)) {
                                            // get rr header size
                                            unsigned header_size = 0;
                                            if(rdata_msg->type == DNSKEY) {
                                                header_size = calc_dnskey_header_size();
                                            }
                                            // RRSIG
                                            else {
                                                header_size = calc_rrsig_header_size(rdata_msg);
                                            }
                                            REQUIRE(memcmp(rdata_msg->data, rdata_frag.data, header_size) == 0); // headers should be the same
                                            
                                            isc_region_t new_rdata_region;
                                            isc_buffer_t *buf = NULL;
                                            unsigned new_rdata_region_length = rdata_msg->length + rdata_frag.length - header_size; 
                                            isc_buffer_allocate(mctx, &buf, new_rdata_region_length); // deduplicate header
                                            isc_buffer_putmem(buf, rdata_msg->data, rdata_msg->length); // copy existing data
                                            isc_buffer_putmem(buf, rdata_frag.data + header_size, rdata_frag.length - header_size); // copy new data (excluding header)
                                            isc_buffer_usedregion(buf, &new_rdata_region); 
                                            rdata_msg->data = new_rdata_region.base;
                                            rdata_msg->length = new_rdata_region.length;
                                            
                                            // not great, but I don't know how to keep track of the buffers otherwise
                                            // maybe its better to create a new dns_message_t object everytime
                                            dns_message_takebuffer(*out_msg, &buf);
                                            goto next_rr;
                                        }
                                    }
                                    rdataset_msg = ISC_LIST_NEXT(rdataset_msg, link);
                                    if(rdataset_msg != NULL) {
                                        tresult_msg = dns_rdataset_first(rdataset_msg); // reset to first rdata
                                    }
                                }
                                result_msg = dns_message_nextname(*out_msg, section); 
                                if (result_msg == ISC_R_SUCCESS) {
                                    name_msg = NULL;
                                    dns_message_currentname(*out_msg, section, &name_msg);
                                    rdataset_msg = ISC_LIST_HEAD(name_msg->list); // reset to first rdataset 
                                    tresult_msg = dns_rdataset_first(rdataset_msg); // reset to first rdata
                                }
                            }
                            //REQUIRE(false); // there should always be a match
                            next_rr:
                        }
                    }
                }
            }
        }
        //isc_buffer_free(&(frag->buffer));
        dns_message_detach(&frag);
    }
    (*out_msg)->from_to_wire = DNS_MESSAGE_INTENTRENDER;
    result = render_fragment(mctx, entry->nr_fragments * 1232, out_msg); // slightly larger than max UDP
    if (result != ISC_R_SUCCESS) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Failed to render the reassembled message!");  
        return result;
    }
    // unset the TC flag so it gets parsed by resolver.c (resquery_response)
    (*out_msg)->flags &= ~DNS_MESSAGEFLAG_TC;
    *(unsigned short *)((*out_msg)->buffer->base + 1) &= ~DNS_MESSAGEFLAG_TC;

    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Reassembled entry %s from %u fragments into one message with size %u", entry->key, entry->nr_fragments, (*out_msg)->buffer->used);  
    
    // would be slightly more efficient to do this in the loop
    result = fcache_remove(fcache, entry->key, entry->keysize);
    if (result != ISC_R_SUCCESS) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
            "Could not remove cache entry after reassembly!");  
        return result;
    }
    return ISC_R_SUCCESS;
}
