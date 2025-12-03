
#include <stdint.h>
#include <sys/types.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/buffer.h>
#include <isc/util.h>
#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/raw_fragmentation.h>

unsigned get_nr_fragments(const unsigned max_msg_size, const unsigned total_msg_size, const unsigned header_size) {
    return (total_msg_size - (header_size + 4)) / max_msg_size; 
}

// clones the rdataset
isc_result_t rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target) {

}

isc_result_t section_clone(dns_message_t *source, dns_message_t *target, unsigned section) {
    REQUIRE(section < DNS_SECTION_MAX);

}

/*
creates and initializes a fragment response by including the following:
1. copy header from message
2. change rcode to 10 (FRAGMENT), 1-9 are taken by RFC1035 and RFC2136
3. copy question from message
4. add an opt record with | frag_nr | nr_fragments | flags |
*/
isc_result_t raw_create_fragment_response(isc_mem_t *mctx, dns_message_t *msg, dns_message_t **frag, unsigned frag_nr, unsigned nr_fragments) {
    REQUIRE(frag != NULL && *frag == NULL);
    dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, frag);
    isc_result_t result;

    // set header metadata
    (*frag)->id = msg->id;
    (*frag)->flags = msg->flags;
    (*frag)->rcode = msg->rcode; // change to fragment
    (*frag)->opcode = msg->opcode;
    (*frag)->rdclass = msg->rdclass;
    // set fragmentation metadata
    (*frag)->is_fragment = true;
    (*frag)->fragment_nr = frag_nr;

    // copy question
    dns_rdataset_t *question = NULL;
    dns_
    dns_message_gettemprdataset(*frag, &question);
    rdataset_clone(msg->, question);
}


isc_result_t raw_create_opt(isc_mem_t *mctx, dns_message_t *msg, dns_message_t **frag, unsigned frag_nr, unsigned nr_fragments, bool truncated) {
    // copy opt if exists, else create new one
    isc_result_t result;
    dns_rdataset_t *opt = NULL;
    dns_rdata_t rdata;
    isc_buffer_t optbuf;
    dns_message_gettemprdataset(*frag, &opt);
    unsigned version = 0; // is this correct?
    uint16_t udpsize = 65535; // max UDP size
    unsigned flags = DNS_MESSAGEEXTFLAG_DO;
    dns_ednsopt_t ednsopts[DNS_EDNSOPTIONS + 1]; // we allow for a max of 9
    size_t opts_count = 0;
    // parse the old opt message
    result = dns_rdataset_first(msg->opt);
    if (result == ISC_R_SUCCESS) {
        // copy buffer
        dns_rdata_init(&rdata);
        dns_rdataset_current(msg->opt, &rdata);
        isc_buffer_init(&optbuf, rdata.data, rdata.length);
        isc_buffer_add(&optbuf, rdata.length);

        // parse count and ednsopts and add to array
        while (isc_buffer_remaininglength(&optbuf) >= 4) {
            REQUIRE(opts_count < DNS_EDNSOPTIONS);
            ednsopts[opts_count].code = isc_buffer_getuint16(&optbuf);
            ednsopts[opts_count].length = isc_buffer_getuint16(&optbuf);
            ednsopts[opts_count].value = isc_buffer_current(&optbuf);
            opts_count++;
        }

        // copy values
        version = msg->opt->ttl >> 16;
        flags = msg->opt->ttl & 0xffff;
        udpsize = msg->opt->rdclass;
    }
    // add the new opt data
    ednsopts[opts_count].code = RAW_OPT_OPTION;
    ednsopts[opts_count].length = 2;
    // 6 bits for frag_nr, 6 bits for nr_fragments, and 4 bits for flags
    uint16_t data = (frag_nr << 10) | (nr_fragments << 4) | (truncated ? 1 : 0);
    unsigned char value[2];
    value[0] = (data >> 8);
    value[1] = data & 0xff;
    ednsopts[opts_count].value = value;

    // build and set opt record
    dns_message_buildopt(*frag, &opt, version, udpsize, flags, ednsopts, opts_count);
    return dns_message_setopt(*frag, opt);
}

bool raw_fragment(isc_mem_t *mctx, dns_message_t *msg, char *client_address) {

    isc_result_t result;
    unsigned msgsize = msg->buffer->used;
    
    // calculate header and question size
    unsigned header_size = 12;
    unsigned question_size = 0;
    for (unsigned i = 0; i < msg->counts[DNS_SECTION_QUESTION]; i++) {

    }

    // calculate overhead


    unsigned start = 0;
    unsigned frag_length;
    for (unsigned frag_nr = 0; frag_nr < nr_fragments; frag_nr++) {    
        isc_buffer_t *frag_buf = NULL;
        frag_length =  msgsize - start < 1232 ? (msgsize - start) : 1232;
        isc_buffer_allocate(mctx, &frag_buf, frag_length); // allocate

        // copy header and question
        isc_buffer_putmem(frag_buf, msg->buffer->base, header_size + question_size);

        // copy body

        // handle OPT record



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

        start += frag_length;

    }



    if (nr_fragments == 1) { 
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "DNSMessage does not need UDP fragmentation!");  
        return false;
    }

    // 0-initialized array of offsets
    unsigned **offsets = isc_mem_get(mctx, DNS_SECTION_MAX * sizeof(unsigned *));
    for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
        offsets[section_nr] = isc_mem_get(mctx, msg->counts[section_nr] * sizeof(unsigned));
        memset(offsets[section_nr], 0, msg->counts[section_nr] * sizeof(unsigned));
    }

    // create cache key
    unsigned char key[69];
    unsigned keysize = sizeof(key) / sizeof(key[0]);
    fcache_create_key(msg->id, client_address, key, &keysize);

    dns_name_t *name = NULL;
    // adding fragment to cache
    for (unsigned frag_nr = 0; frag_nr < nr_fragments; frag_nr++) {        
        dns_message_t *frag = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &frag);

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
            if(msg->counts[section_nr] > 0) {
                for (isc_result_t result = dns_message_firstname(msg, section_nr); result == ISC_R_SUCCESS;  result = dns_message_nextname(msg, section_nr))
                {
                    name = NULL;
                    dns_message_currentname(msg, section_nr, &name);
                    dns_name_t *new_name = NULL;
                    dns_message_gettempname(frag, &new_name);
                    
                    // change the name from x.com to ?fragment?x.com
                    // we don't do this for the first fragment
                    if (frag_nr > 0) {
                        char *name_str = NULL;
                        dns_name_tostring(name, &name_str, mctx);
                        unsigned new_name_str_len = strlen(name_str) + 4;
                        char *new_name_str = isc_mem_get(mctx, new_name_str_len);
                        snprintf(new_name_str, new_name_str_len, "?%u?%s", frag_nr + 1, name_str); // + 1 because fragments start from 1
                        dns_name_fromstring(new_name, new_name_str, name, 0, mctx);
                        // clean up
                        isc_mem_free(mctx, name_str);
                        isc_mem_put(mctx, new_name_str, new_name_str_len);
                    }
                    else {
                        dns_name_copy(name, new_name);
                    }

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
                                    calculate_start_end(frag_nr, nr_fragments, offsets[section_nr][counter], rdsize_no_header, can_send_first_fragment, can_send_other_fragments, total_sig_pk_bytes_per_frag, rr_pk_sig_count, &new_rdata_start, &new_rdata_length);

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
                            // already added in first fragment
                            else {
                                savings += rdata.length; // do we need to include this? And is it with or without header?
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
                        REQUIRE(msg->counts[DNS_SECTION_QUESTION == 1]); // too strict?
                    }
                    dns_message_addname(frag, new_name, section_nr);
                }
            }
            // can be moved, but leads to sanity check issues
            // OPT record found!
            // only one allowed and can only be in the additional section
            if (msg->opt != NULL && section_nr == DNS_SECTION_ADDITIONAL) {
                REQUIRE(dns_rdataset_count(msg->opt) == 1);
                dns_rdataset_t *new_opt_rdataset = NULL;
                dns_message_gettemprdataset(frag, &new_opt_rdataset);

                // get first rdata from msg->opt
                REQUIRE(dns_rdataset_first(msg->opt) == ISC_R_SUCCESS); // there should be one resource record
                dns_rdata_t rdata = DNS_RDATA_INIT;
                dns_rdataset_current(msg->opt, &rdata);
                isc_region_t rdata_region;
                dns_rdata_toregion(&rdata, &rdata_region);

                // prepare new rdata
                dns_rdata_t *new_opt_rdata = NULL;
                dns_message_gettemprdata(frag, &new_opt_rdata);
                dns_rdata_fromregion(new_opt_rdata, rdata.rdclass, rdata.type, &rdata_region); 

                // add to new rdataset and fragmentfrag
                dns_rdatalist_t *rdatalist = NULL;
                dns_message_gettemprdatalist(frag, &rdatalist);
                ISC_LIST_APPEND(rdatalist->rdata, new_opt_rdata, link);
                // copy values
                rdatalist->rdclass = msg->opt->rdclass;
                rdatalist->type = msg->opt->type;
                rdatalist->ttl = msg->opt->ttl; 
                dns_rdatalist_tordataset(rdatalist, new_opt_rdataset);
                REQUIRE(dns_message_setopt(frag, new_opt_rdataset) == ISC_R_SUCCESS);
                new_section_count++;
                counter++;
            }

            REQUIRE(counter == msg->counts[section_nr]); 
            frag->counts[section_nr] = new_section_count;
        }
	    REQUIRE(DNS_MESSAGE_VALID(frag));
        render_fragment(mctx, 1280, &frag); // slightly larger than max UDP
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
                "Adding fragment %u of length %u for message %u to cache...", frag_nr, frag->buffer->used, frag->id);  
        fcache_add(key, keysize, frag, nr_fragments);
        printf("frag %u\n", frag_nr + 1);
        printmessage(mctx, frag);
		for (unsigned i = 0; i < frag->buffer->used; i++) {
			printf("%02X ", ((unsigned char *)(frag->buffer->base))[i]);
		}
		printf("\n");
        dns_message_detach(&frag);
    }

    // free memory
    for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
        isc_mem_put(mctx, offsets[section_nr], msg->counts[section_nr] * sizeof(unsigned));
    }
    isc_mem_put(mctx, offsets, DNS_SECTION_MAX * sizeof(unsigned *));

    return true;

}