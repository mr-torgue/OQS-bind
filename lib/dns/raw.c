
#include <stdint.h>
#include <sys/types.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/buffer.h>
#include <isc/util.h>
#include <dns/message.h>
#include <dns/rdata.h>
#include <dns/fcache.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/udp_fragmentation.h>
#include <dns/raw.h>

static isc_result_t raw_create_fragment_response(isc_mem_t *mctx, dns_message_t *msg, dns_message_t **frag, const unsigned frag_nr, const unsigned nr_fragments, const unsigned fragment_flags);
static isc_result_t raw_create_opt(isc_mem_t *mctx, dns_message_t *msg, dns_message_t *frag, unsigned frag_nr, unsigned nr_fragments, unsigned fragment_flags);
static isc_result_t raw_get_sizes_offsets(isc_buffer_t *frag_buf, unsigned *body_offset, unsigned *body_size,
                                          unsigned *opt_offset, unsigned *opt_size,
                                          unsigned *first_rr_offset, unsigned *last_rr_offset,
                                          bool *is_truncated);


/*
every fragment needs a header, question, and opt record (maybe some other fields?)
so, we can send `max_msg_size` - `fixed` bytes in each fragment
*/
unsigned get_nr_fragments(const unsigned max_msg_size, const unsigned total_msg_size, const unsigned header_size, const unsigned question_size, const unsigned opt_size) {
    unsigned fixed_size = header_size + question_size + opt_size;
    REQUIRE(max_msg_size > fixed_size);
    unsigned body_size = total_msg_size - fixed_size; // amount of bytes to send
    unsigned payload_size = max_msg_size - fixed_size;
return ((body_size + payload_size - 1) / payload_size);
}


/*
creates and initializes a fragment response by including the following:
1. copy header from message
2. change rcode to 12 (FRAGMENT), 1-9 are taken by RFC1035 and RFC2136
3. copy question from message
4. set opt
*/
static isc_result_t raw_create_fragment_response(isc_mem_t *mctx, dns_message_t *msg, dns_message_t **frag, const unsigned frag_nr, const unsigned nr_fragments, const unsigned fragment_flags) {
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
    fprintf(stderr,
        "DEBUG: source question count=%u\n",
        msg->counts[DNS_SECTION_QUESTION]);
    result = section_clone(msg, *frag, DNS_SECTION_QUESTION);
    if (result != ISC_R_SUCCESS) {
        perror("Could not clone DNS_QUESTION_SECTION!\n");
        return result;
    }
    result = create__fragment_opt(*frag, frag_nr, nr_fragments, fragment_flags, false);
    if (result != ISC_R_SUCCESS) {
        perror("Could not create OPT record!\n");
        return result;
    }
    return ISC_R_SUCCESS;
}


static isc_result_t raw_create_opt(isc_mem_t *mctx, dns_message_t *msg, dns_message_t *frag, unsigned frag_nr, unsigned nr_fragments, unsigned fragment_flags) {
    // copy opt if exists, else create new one
    isc_result_t result;
    dns_rdataset_t *opt = NULL;
    dns_rdata_t rdata;
    isc_buffer_t optbuf;
  //  dns_message_gettemprdataset(frag, &opt);
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
    uint16_t data = (frag_nr << 10) | (nr_fragments << 4) | (fragment_flags & 0xf);
    unsigned char value[2];
    value[0] = (data >> 8);
    value[1] = data & 0xff;
    ednsopts[opts_count].value = value;
    opts_count++;

    // build and set opt record
    result = dns_message_buildopt(frag, &opt, version, udpsize, flags, ednsopts, opts_count);
    	
	if (result != ISC_R_SUCCESS) {
    return result;
}

	return dns_message_setopt(frag, opt);
}

isc_result_t raw_fragment(isc_mem_t *mctx, fcache_t *fcache, dns_message_t *msg, char *client_address, const unsigned max_udp_size) {
    fprintf(stderr,
            "DEBUG raw_fragment entry: buffer=%p used=%u question=%u answer=%u authority=%u additional=%u\n",
            (void *)msg->buffer,
            msg->buffer != NULL ? msg->buffer->used : 0,
            msg->counts[DNS_SECTION_QUESTION],
            msg->counts[DNS_SECTION_ANSWER],
            msg->counts[DNS_SECTION_AUTHORITY],
            msg->counts[DNS_SECTION_ADDITIONAL]);

    isc_result_t result;


    if (msg->buffer == NULL) {
    result = render_fragment(mctx, max_udp_size * 64, &msg);
    if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
        return result;
    }
}

    unsigned msgsize = msg->buffer -> used;
    unsigned char key[69];
    unsigned keysize = sizeof(key) / sizeof(key[0]);
    fcache_create_key(msg->id, client_address, key, &keysize);


    if (fcache_exists(fcache, key, keysize)) {

	return ISC_R_EXISTS;
    }

    
    // calculate header and question size
    unsigned header_size = DNS_HEADER_SIZE;
    unsigned question_size = 0; // TODO
    unsigned opt_size = 0; // TODO
    unsigned nr_fragments = get_nr_fragments(max_udp_size, msgsize, header_size, question_size, opt_size);
	fprintf(stderr,
        "DEBUG: msgsize=%u max_udp_size=%u nr_fragments=%u\n",
        msgsize,
        max_udp_size,
        nr_fragments);

	if (nr_fragments <= 1) {
    fprintf(stderr,
            "DEBUG: response fits in one UDP packet; skipping RAW fragmentation\n");
   dns_message_renderreset(msg);    

return ISC_R_NOTFOUND;
}

	result = fcache_add(fcache, key, keysize, nr_fragments);
    if (result != ISC_R_SUCCESS) {
        return result;
    }

	unsigned available_per_fragment = max_udp_size - header_size - question_size - opt_size;

    // create fragment
    unsigned frag_nr = 0;
    dns_message_t *frag = NULL;
    unsigned fragment_flags = 0;
    raw_create_fragment_response(mctx, msg, &frag, frag_nr, nr_fragments, 0);
	result = render_fragment(mctx, max_udp_size, &frag);
if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
    return result;
}

result = fcache_add_fragment(fcache, key, keysize, frag);
if (result != ISC_R_SUCCESS) {
    return result;
}

fprintf(stderr,
        "DEBUG: cached initial fragment=0\n");

fprintf(stderr,
        "DEBUG: frag0 first question result=%d\n",
        dns_message_firstname(frag, DNS_SECTION_QUESTION));
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
dns_rdatalist_t *rdatalist = NULL;

dns_message_gettemprdataset(frag, &new_rdataset);
dns_message_gettemprdatalist(frag, &rdatalist);

rdatalist->rdclass = rdataset->rdclass;
rdatalist->type = rdataset->type;
rdatalist->ttl = rdataset->ttl;




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
 
			if (frag_nr == 0) {
    result = render_fragment(mctx, max_udp_size, &frag);
    if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
        return result;
    }

    result = fcache_add_fragment(fcache, key, keysize, frag);
    if (result != ISC_R_SUCCESS) {
        return result;
    }

    fprintf(stderr,
            "DEBUG: cached initial fragment=0\n");
}



                       dns_message_addname(frag, new_name, section);
                        
                        // reset name
                        new_name = NULL;
                        dns_message_gettempname(frag, &new_name);       
                        dns_name_clone(name, new_name);   
                        result = render_fragment(mctx, max_udp_size, &frag);
if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
	return result;
}
			result = fcache_add_fragment(fcache, key, keysize, frag);
			if (result != ISC_R_SUCCESS) {
                        	return result;
                        }
	fprintf(stderr,
        "DEBUG: cached fragment=%u  second\n",
        frag_nr);

			// reset frag
                        start = 0;
                        frag = NULL;
                        raw_create_fragment_response(mctx, msg, &frag, frag_nr, nr_fragments, 0);
                        

			new_name = NULL;
			dns_message_gettempname(frag, &new_name);
			dns_name_clone(name, new_name);
	
			new_rdataset = NULL;
			dns_message_gettemprdataset(frag, &new_rdataset);

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
    dns_message_addname(frag, new_name, section);

    result = render_fragment(mctx, max_udp_size, &frag);
    if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
        return result;
    }

    result = fcache_add_fragment(fcache, key, keysize, frag);
    if (result != ISC_R_SUCCESS) {
        return result;
    }

    start = 0;
	fprintf(stderr,
        "DEBUG: second split increment frag_nr from %u\n",
        frag_nr);
    frag_nr++;
    frag = NULL;
    raw_create_fragment_response(mctx, msg, &frag, frag_nr, nr_fragments, 0);

    new_name = NULL;
    dns_message_gettempname(frag, &new_name);
    dns_name_clone(name, new_name);

    new_rdataset = NULL;
    rdatalist = NULL;
    dns_message_gettemprdataset(frag, &new_rdataset);
    dns_message_gettemprdatalist(frag, &rdatalist);

    rdatalist->rdclass = rdataset->rdclass;
    rdatalist->type = rdataset->type;
    rdatalist->ttl = rdataset->ttl;

    start += RR_HEADER_SIZE;
    if (!name->attributes.nocompress) {
        start += 2;
    } else {
        start += name->length;
    }
}

ISC_LIST_APPEND(rdatalist->rdata, new_rdata, link);
start += rdata.length;



			tresult = dns_rdataset_next(rdataset);
                    }
                }
            }      
                
        }
    }

	fprintf(stderr,
        "DEBUG: finishing fragmentation frag_nr=%u nr_fragments=%u\n",
        frag_nr,
        nr_fragments);


result = render_fragment(mctx, max_udp_size, &frag);
if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
    return result;
}

<<<<<<< HEAD
=======
/*
 * Store the final fragment in the cache.
 */
result = fcache_add_fragment(fcache, key, keysize, frag);
if (result != ISC_R_SUCCESS) {
    fprintf(stderr,
            "DEBUG: failed to cache final fragment=%u result=%s\n",
            frag_nr,
            isc_result_totext(result));
    return result;
}

fprintf(stderr,
        "DEBUG: cached final fragment=%u\n",
        frag_nr);

>>>>>>> 822c40b526 (Implement client-side RAW OPT fragment caching and reassembly)
unsigned actual_fragments = frag_nr + 1;

fprintf(stderr,
        "DEBUG: actual last frag_nr=%u expected=%u\n",
        frag_nr,
        nr_fragments);

fprintf(stderr,
        "DEBUG: updating fragment count %u -> %u\n",
        nr_fragments,
        actual_fragments);

result = fcache_update_fragment_count(
    fcache, key, keysize, actual_fragments);

if (result != ISC_R_SUCCESS) {
    fprintf(stderr,
            "DEBUG: cache count update failed: %d\n",
            result);
    return result;
}

fprintf(stderr,
        "DEBUG: updated cache fragment count=%u\n",
        actual_fragments);

return ISC_R_SUCCESS;


fprintf(stderr,
"DEBUG: updated cache fragment count=%u\n",
frag_nr + 1);


	fprintf(stderr,
        "DEBUG: cached final fragment=%u\n",
        frag_nr);
    
	fprintf(stderr,
"DEBUG: actual last frag_nr=%u expected=%u\n",
frag_nr,
nr_fragments);


fprintf(stderr,
"DEBUG: updating fragment count %u -> %u\n",
nr_fragments,
actual_fragments);
/* Create/update the cache entry with the actual fragment count */
result = fcache_add(fcache, key, keysize, actual_fragments);
if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS) {
    return result;
}
	return ISC_R_SUCCESS;
}


//
static isc_result_t raw_get_sizes_offsets(isc_buffer_t *frag_buf, unsigned *body_offset, unsigned *body_size,
                                unsigned *opt_offset, unsigned *opt_size,
                                unsigned *first_rr_offset, unsigned *last_rr_offset, bool *is_truncated) 

{
    isc_region_t frag_region;
    isc_buffer_usedregion(frag_buf, &frag_region);

    unsigned qdcount = frag_region.base[4] << 8 | frag_region.base[5];
    unsigned arcount = frag_region.base[10] << 8 | frag_region.base[11];
    unsigned msg_size = DNS_HEADER_SIZE;

    for (unsigned i = 0; i < qdcount; i++) {
        msg_size += calc_name_size(frag_region.base + msg_size,
                                   frag_region.length - msg_size);
        msg_size += QUESTION_HEADER_SIZE;
    }

    *body_offset = msg_size;
	/*
 * The RAW OPT RR is currently expected to be the final additional
 * record in each fragment.
 *
 * OPT fixed RR fields:
 *   root name  = 1 byte
 *   type       = 2 bytes
 *   class      = 2 bytes
 *   TTL        = 4 bytes
 *   RDLENGTH   = 2 bytes
 * Total fixed header = 11 bytes
 *
 * RAW EDNS option:
 *   option code   = 2 bytes
 *   option length = 2 bytes
 *   option value  = 2 bytes
 * Total RAW option = 6 bytes
 */
if (arcount > 0 && frag_region.length >= 17) {
    *opt_size = 17;
    *opt_offset = frag_region.length - *opt_size;
    *body_size = (*opt_offset > *body_offset)
                     ? (*opt_offset - *body_offset)
                     : 0;
}
     else {
        *opt_offset = 0;
        *opt_size = 0;
        *body_size = (frag_region.length > *body_offset)
                         ? (frag_region.length - *body_offset)
                         : 0;
    }

    *first_rr_offset = *body_offset;
*last_rr_offset = *body_offset;

unsigned scan = *body_offset;
unsigned body_end = *body_offset + *body_size;
bool found_rr = false;

while (scan < body_end) {
    unsigned rr_start = scan;
    unsigned name_size = calc_name_size(frag_region.base + scan,
                                        frag_region.length - scan);

    if (scan + name_size + RR_HEADER_SIZE > body_end) {
        break;
    }

    unsigned rdlength_index = scan + name_size + 8;
    unsigned rdlength = (frag_region.base[rdlength_index] << 8) |
                        frag_region.base[rdlength_index + 1];

    unsigned rr_end = scan + name_size + RR_HEADER_SIZE + rdlength;
    if (rr_end > body_end) {
        break;
    }

    if (!found_rr) {
        *first_rr_offset = rr_start;
        found_rr = true;
    }

    *last_rr_offset = rdlength_index;
    scan = rr_end;
}
    *is_truncated = false;

	if (*opt_size >= 17 &&
    *opt_offset + *opt_size <= frag_region.length)
{
    unsigned char *opt = frag_region.base + *opt_offset;

    unsigned opt_type = ((unsigned)opt[1] << 8) | opt[2];
    unsigned rdlen = ((unsigned)opt[9] << 8) | opt[10];

    /*
     * DNS_TYPE_OPT is 41.
     * Ensure the calculated offset really points to an OPT RR.
     */
    if (opt_type == 41 && rdlen >= 6 &&
        11U + rdlen <= *opt_size)
    {
        unsigned char *option = opt + 11;
        unsigned option_code =
            ((unsigned)option[0] << 8) | option[1];
        unsigned option_len =
            ((unsigned)option[2] << 8) | option[3];

        if (option_code == RAW_OPT_OPTION &&
            option_len == 2 &&
            4U + option_len <= rdlen)
        {
            unsigned value =
                ((unsigned)option[4] << 8) | option[5];

            unsigned flags = value & 0x0f;
            *is_truncated =
                ((flags & RAW_FLAG_RRTR) != 0);
        }
    }
}

    return ISC_R_SUCCESS;
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
    isc_result_t result;
    // check if all fragments are in cache
    if (entry->bitmap != (1u << entry->nr_fragments) - 1) {    
    return ISC_R_INPROGRESS;
    }

    isc_buffer_t *out_buf = NULL;
    isc_buffer_allocate(mctx, &out_buf, entry->nr_fragments * 1232);
    bool is_truncated = false;
bool prev_is_truncated = false;
unsigned truncated_rdlength_index = 0;
unsigned truncated_rdlength = 0;
unsigned rdlength_index = 0;
unsigned rdlength = 0;
unsigned char *saved_opt_base = NULL;
unsigned saved_opt_size = 0;

    //bool prev_is_truncated = false;
    //unsigned truncated_rdlength_index, truncated_rdlength;
    //unsigned rdlength_index, rdlength; // keeps track of the rr's truncated rdlength and index relative to frag buffer
    for(unsigned frag_nr = 0; frag_nr < entry->nr_fragments; frag_nr++) {
        // get isc_buffer_t from cache
        isc_buffer_t *frag_buf = entry->fragments[frag_nr];
        unsigned opt_offset, opt_size, body_offset, body_size, first_rr_offset, last_rr_offset;
        raw_get_sizes_offsets(frag_buf, &body_offset, &body_size, &opt_offset, &opt_size, &first_rr_offset, &last_rr_offset, &is_truncated);
         
        /* Save the OPT record from the first fragment. */
if (frag_nr == 0 && opt_size > 0) {
    saved_opt_base = ((unsigned char *)frag_buf->base) + opt_offset;
    saved_opt_size = opt_size;
}        
        // copy question if first fragment
        if (frag_nr == 0) {
            isc_buffer_putmem(out_buf, frag_buf->base, body_offset); 

        }

	if (is_truncated && prev_is_truncated) {
    rdlength_index = last_rr_offset;
    rdlength = (((unsigned char *)(frag_buf->base))[rdlength_index] << 8) |
               ((unsigned char *)(frag_buf->base))[rdlength_index + 1];
    truncated_rdlength += rdlength;
}
else if (is_truncated) {
    rdlength_index = last_rr_offset;
    rdlength = (((unsigned char *)(frag_buf->base))[rdlength_index] << 8) |
               ((unsigned char *)(frag_buf->base))[rdlength_index + 1];
    truncated_rdlength_index = rdlength_index;
    truncated_rdlength = rdlength;
    prev_is_truncated = true;
}

else if (prev_is_truncated) {
    rdlength_index = first_rr_offset;
    rdlength = (((unsigned char *)(frag_buf->base))[rdlength_index] << 8) |
               ((unsigned char *)(frag_buf->base))[rdlength_index + 1];

    truncated_rdlength += rdlength;

    ((unsigned char *)(out_buf->base))[truncated_rdlength_index] =
        truncated_rdlength >> 8;
    ((unsigned char *)(out_buf->base))[truncated_rdlength_index + 1] =
        truncated_rdlength & 0xff;

    prev_is_truncated = false;
}


 /*   
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
        }*/
        isc_buffer_putmem(out_buf, ((unsigned char *)frag_buf->base) + body_offset, body_size); 
    }

        /* Reattach the OPT record after reconstructing the body. */
if (saved_opt_base != NULL && saved_opt_size > 0) {
    isc_buffer_putmem(out_buf, saved_opt_base, saved_opt_size);
}


        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, out_msg);
isc_buffer_first(out_buf);
result = dns_message_parse(*out_msg, out_buf, DNS_MESSAGEPARSE_IGNORETRUNCATION);
if (result != ISC_R_SUCCESS) {
    dns_message_detach(out_msg);
    return result;
}

return ISC_R_SUCCESS;
}

