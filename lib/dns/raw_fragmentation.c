
#include <stdint.h>
#include <sys/types.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/buffer.h>
#include <isc/util.h>
#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/raw_fragmentation.h>

/*
every fragment needs a header, question, and opt record (maybe some other fields?)
so, we can send `max_msg_size` - `fixed` bytes in each fragment
*/
unsigned get_nr_fragments(const unsigned max_msg_size, const unsigned total_msg_size, const unsigned header_size, const unsigned question_size, const unsigned opt_size) {
    unsigned fixed_size = header_size + question_size + opt_size;
    REQUIRE(max_msg_size > fixed_size);
    unsigned body_size = total_msg_size - fixed_size; // amount of bytes to send
    return body_size / (max_msg_size - fixed_size); 
}


/*
creates and initializes a fragment response by including the following:
1. copy header from message
2. change rcode to 12 (FRAGMENT), 1-9 are taken by RFC1035 and RFC2136
3. copy question from message
4. set opt
*/
isc_result_t raw_create_fragment_response(isc_mem_t *mctx, dns_message_t *msg, dns_message_t **frag, const unsigned frag_nr, const unsigned nr_fragments) {
    REQUIRE(frag != NULL && *frag == NULL);
    dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, frag);
    isc_result_t result;

    // set header metadata
    (*frag)->id = msg->id;
    (*frag)->flags = msg->flags;
    (*frag)->rcode = RAW_RCODE;
    (*frag)->opcode = msg->opcode;
    (*frag)->rdclass = msg->rdclass;
    // set fragmentation metadata
    (*frag)->is_fragment = true;
    (*frag)->fragment_nr = frag_nr;

    // copy question
    dns_rdataset_t *question = NULL;
    dns_message_gettemprdataset(*frag, &question);
    result = section_clone(msg, *frag, DNS_SECTION_QUESTION);
    if (result != ISC_R_SUCCESS) {
        perror("Could not clone DNS_QUESTION_SECTION!\n");
        return result;
    }
    result = raw_create_opt(mctx, msg, *frag, frag_nr, nr_fragments);
    if (result != ISC_R_SUCCESS) {
        perror("Could not create OPT record!\n");
        return result;
    }
    return ISC_R_SUCCESS;
}


isc_result_t raw_create_opt(isc_mem_t *mctx, dns_message_t *msg, dns_message_t *frag, unsigned frag_nr, unsigned nr_fragments) {
    // copy opt if exists, else create new one
    isc_result_t result;
    dns_rdataset_t *opt = NULL;
    dns_rdata_t rdata;
    isc_buffer_t optbuf;
    dns_message_gettemprdataset(frag, &opt);
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
    uint16_t data = (frag_nr << 10) | (nr_fragments << 4);
    unsigned char value[2];
    value[0] = (data >> 8);
    value[1] = data & 0xff;
    ednsopts[opts_count].value = value;

    // build and set opt record
    dns_message_buildopt(frag, &opt, version, udpsize, flags, ednsopts, opts_count);
    return dns_message_setopt(frag, opt);
}

bool raw_fragment(isc_mem_t *mctx, dns_message_t *msg, char *client_address) {

    isc_result_t result;
    unsigned msgsize = msg->buffer->used;
    
    // calculate header and question size
    unsigned header_size = DNS_HEADER_SIZE;
    unsigned question_size = 0; // TODO
    unsigned opt_size = 0; // TODO
    unsigned nr_fragments = get_nr_fragments(1232, msgsize, header_size, question_size, opt_size);
    unsigned available_per_fragment = msgsize - header_size - question_size - opt_size;

    // create fragment
    unsigned frag_nr = 0;
    dns_message_t *frag = NULL;
    raw_create_fragment_response(mctx, msg, &frag, frag_nr, nr_fragments);

    unsigned start = 0;
    for (unsigned section = DNS_SECTION_ANSWER; section < DNS_SECTION_MAX; section++) {
        for (isc_result_t result = dns_message_firstname(msg, section); 
             result == ISC_R_SUCCESS;  
             result = dns_message_nextname(msg, section)) {
            dns_name_t *name = NULL;
            dns_message_currentname(msg, section, &name);
            dns_name_t *new_name = NULL;
            dns_message_gettempname(frag, &new_name);         
            dns_name_clone(name, new_name);
            //dns_message_addname(frag, new_name, section);
            
            for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                bool reset = false;
                dns_rdataset_t *new_rdataset = NULL;
                dns_message_gettemprdataset(frag, &new_rdataset);   
                //ISC_LIST_APPEND(new_name->list, new_rdataset, link);

                isc_result_t tresult = dns_rdataset_first(rdataset);
                while (tresult == ISC_R_SUCCESS) {
                    dns_rdata_t rdata = DNS_RDATA_INIT;
                    dns_rdataset_current(rdataset, &rdata);
                    // calculate header size
                    start += RR_HEADER_SIZE;
                    if (!name->attributes.nocompress) { 
                        start += 2; // compressed name only takes two bytes
                    }
                    else {
                        start += name->length;
                    }
                    // if does not fit, go to next fragment
                    if (start > available_per_fragment) {
                        REQUIRE(!reset); // loop detection
                        dns_message_addname(frag, new_name, section);
                        
                        // reset name
                        new_name = NULL;
                        dns_message_gettempname(frag, &new_name);       
                        dns_name_clone(name, new_name);   

                        fcache_add(key, keysize, frag);
                        // reset frag
                        start = 0;
                        frag_nr++;
                        frag = NULL;
                        raw_create_fragment_response(mctx, msg, &frag, frag_nr, nr_fragments);
                        reset = true;
                        // don't go to next rdata
                    }
                    else {
                        reset = false;
                        dns_rdata_t *new_rdata = NULL;
                        dns_message_gettemprdata(frag, &new_rdata);
                        dns_rdata_clone(&rdata, new_rdata);
                        // not enough space, truncate
                        if (start + rdata.length > available_per_fragment) {
                            unsigned new_rdata_length = available_per_fragment - start;
                            unsigned remaining = rdata.length - new_rdata_length;

                            new_rdata->length = new_rdata_length;
                            // do we need to copy?
                            if (new_rdata_length > 0) {
                                isc_region_t rdata_region;
                                dns_rdata_toregion(&rdata, &rdata_region);
                                isc_region_t new_rdata_region;
                                isc_buffer_t *new_rdata_buf = NULL;
                                isc_buffer_allocate(mctx, &new_rdata_buf, new_rdata_length);
                                isc_buffer_putmem(new_rdata_buf, rdata_region.base, new_rdata_length); 
                                isc_buffer_usedregion(new_rdata_buf, &new_rdata_region); 
                                dns_rdata_fromregion(new_rdata, rdata.rdclass, rdata.type, &new_rdata_region); 
                                dns_message_takebuffer(msg, &new_rdata_buf);
                            }
                            ISC_LIST_APPEND(new_rdataset->rdlist.list->rdata, new_rdata, link); 
                            dns_message_addname(frag, new_name, section);
                            // reset frag
                            start = 0;
                            frag_nr++;
                            frag = NULL;
                            raw_create_fragment_response(mctx, msg, &frag, frag_nr, nr_fragments);
                        }
                        tresult = dns_rdataset_next(rdataset);
                    }
                }
            }      
                
        }
    }
    return true;
}


//
isc_result_t raw_get_sizes_offsets(isc_buffer_t *frag_buf, unsigned *body_offset, unsigned *body_size, 
                                unsigned *opt_offset, unsigned *opt_size, 
                                unsigned *first_rr_offset, unsigned *last_rr_offset, bool *is_truncated) {
    isc_region_t frag_region;
    isc_buffer_usedregion(frag_buf, &frag_region);
    unsigned qdcount = frag_region.base[4] << 8 | frag_region.base[5];
    unsigned ancount = frag_region.base[6] << 8 | frag_region.base[7];
    unsigned nscount = frag_region.base[8] << 8 | frag_region.base[9];
    unsigned arcount = frag_region.base[10] << 8 | frag_region.base[11];
    unsigned rdlength;

    // calculate question
    unsigned msg_size = DNS_HEADER_SIZE;
    for(unsigned i = 0; i < qdcount; i++) {
        msg_size += calc_name_size(frag_region.base + msg_size, (frag_region.length - msg_size));
        msg_size += QUESTION_HEADER_SIZE;
    }
    *body_offset = msg_size;

    for (unsigned section = DNS_SECTION_ANSWER; section < DNS_SECTION_MAX; section++) {
        msg_size += calc_name_size(frag_region.base + msg_size, (frag_region.length - msg_size));
        msg_size += RR_HEADER_SIZE;
        rdlength = frag_region.base[msg_size - 2] << 8 | frag_region.base[msg_size - 1];
        msg_size += rdlength;
        if (section == DNS_SECTION_ADDITIONAL && )
    }


}

/*
reassemble happens when the resolver has received all fragments
most of the fragments are stored as a byte buffer
we cannot simply concatenate, because we need to copy the OPT record

flow:
1. resolver receives raw buffers, so no dns_message_t
2. resquery_response expects a region, so we don't need to generate a dns_message_T
*/
isc_result_t raw_reassemble_fragments(isc_mem_t *mctx, fragment_cache_entry_t *entry, dns_message_t **out_msg) {
    REQUIRE(entry != NULL);
    REQUIRE(out_msg != NULL && *out_msg == NULL);

    // check if all fragments are in cache
    if (entry->bitmap != (1u << entry->nr_fragments) - 1) {    
        perror("Not all fragments have been received for entry %s (bitmap: %lx)", entry->key, entry->bitmap);  
        return ISC_R_FAILURE;
    }

    isc_buffer_t *out_buf = NULL;
    isc_buffer_allocate(mctx, &out_buf, entry->nr_fragments * 1232);
    bool is_truncated = false;
    bool prev_is_truncated = false;
    unsigned truncated_rdlength_index, truncated_rdlength;
    unsigned rdlength_index, rdlength; // keeps track of the rr's truncated rdlength and index relative to frag buffer
    for(unsigned frag_nr = 0; frag_nr < entry->nr_fragments; frag_nr++) {
        // get isc_buffer_t from cache
        isc_buffer_t *frag_buf = entry->fragments[frag_nr];
        unsigned opt_offset, opt_size, body_offset, body_size, first_rr_offset, last_rr_offset;
        get_sizes_offsets(frag_buf, &body_offset, &body_size, &opt_offset, &opt_size, &first_rr_offset, &last_rr_offset, &is_truncated);
        
        // copy question if first fragment
        if (frag_nr == 0) {
            isc_buffer_putmem(out_buf, frag_buf->base, body_offset); 
        }
    
        // it is possible that one RR needs multiple fragments
        if (is_truncated && prev_is_truncated) {
            rdlength_index = last_rr_offset + x;
            rdlength = (((unsigned char*)(frag_buf->base))[rdlength_index] << 8 | ((unsigned char*)(frag_buf->base))[rdlength_index + 1]);
            truncated_rdlength += rdlength;
        }
        else if (is_truncated) {
            rdlength_index = last_rr_offset + x;
            rdlength = (((unsigned char*)(frag_buf->base))[rdlength_index] << 8 | ((unsigned char*)(frag_buf->base))[rdlength_index + 1]);
            truncated_rdlength_index = rdlength_index;
            truncated_rdlength += rdlength;
            prev_is_truncated = true;
        }
        else if (prev_is_truncated) {
            rdlength_index = last_rr_offset + x;
            rdlength = (((unsigned char*)(frag_buf->base))[rdlength_index] << 8 | ((unsigned char*)(frag_buf->base))[rdlength_index + 1]);
            truncated_rdlength += rdlength;
            ((unsigned char*)(out_buf->base))[truncated_rdlength_index] = truncated_rdlength >> 8;
            ((unsigned char*)(out_buf->base))[truncated_rdlength_index + 1] = truncated_rdlength & 0xffff;
            prev_is_truncated = false;
        }
        else { // I don't think we need this clause
            prev_is_truncated = false;
        }
        isc_buffer_putmem(out_buf, frag_buf->base + body_offset, body_size); 
    }
    // recreate and attach OPT
}