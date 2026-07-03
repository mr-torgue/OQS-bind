
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
                                unsigned *first_rr_offset, unsigned *last_rr_offset, bool *is_truncated)

{
    isc_region_t frag_region;
    isc_buffer_usedregion(frag_buf, &frag_region);
    unsigned char *base = (unsigned char *)frag_region.base;

    if (frag_region.length < DNS_HEADER_SIZE) {
        return ISC_R_FAILURE;
    }

    unsigned qdcount = base[4] << 8 | base[5];
    unsigned ancount = base[6] << 8 | base[7];
    unsigned nscount = base[8] << 8 | base[9];
    unsigned arcount = base[10] << 8 | base[11];
    unsigned msg_size = DNS_HEADER_SIZE;

    for (unsigned i = 0; i < qdcount; i++) {
        unsigned name_size = calc_name_size(base + msg_size,
                                            frag_region.length - msg_size);
        if (msg_size + name_size + QUESTION_HEADER_SIZE > frag_region.length) {
            return ISC_R_FAILURE;
        }
        msg_size += name_size + QUESTION_HEADER_SIZE;
    }

    *body_offset = msg_size;
    *body_size = 0;
    *opt_offset = 0;
    *opt_size = 0;
    *first_rr_offset = msg_size;
    *last_rr_offset = msg_size;
    *is_truncated = false;

    unsigned rr_count = ancount + nscount + arcount;
    bool have_rr = false;

    for (unsigned i = 0; i < rr_count; i++) {
        unsigned rr_start = msg_size;
        unsigned name_size = calc_name_size(base + msg_size,
                                            frag_region.length - msg_size);

        if (msg_size + name_size + RR_HEADER_SIZE > frag_region.length) {
            return ISC_R_FAILURE;
        }

        unsigned type_offset = msg_size + name_size;
        unsigned rrtype = base[type_offset] << 8 | base[type_offset + 1];
        unsigned rdlength_index = msg_size + name_size + 8;
        unsigned rdlength = base[rdlength_index] << 8 | base[rdlength_index + 1];
        unsigned rr_end = msg_size + name_size + RR_HEADER_SIZE + rdlength;

        if (rr_end > frag_region.length) {
            return ISC_R_FAILURE;
        }

        /* OPT RR type is 41. Treat it as the fragment metadata record. */
        if (rrtype == 41) {
            *opt_offset = rr_start;
            *opt_size = rr_end - rr_start;
            *body_size = rr_start - *body_offset;

            unsigned option_offset = msg_size + name_size + RR_HEADER_SIZE;
            unsigned option_end = option_offset + rdlength;

            while (option_offset + 4 <= option_end) {
                unsigned option_code = base[option_offset] << 8 | base[option_offset + 1];
                unsigned option_len = base[option_offset + 2] << 8 | base[option_offset + 3];
                option_offset += 4;

                if (option_offset + option_len > option_end) {
                    return ISC_R_FAILURE;
                }

                if (option_code == RAW_OPT_OPTION && option_len == 2) {
                    unsigned value = base[option_offset] << 8 | base[option_offset + 1];
                    unsigned flags = value & 0xf;
                    *is_truncated = ((flags & RAW_FLAG_RRTR) != 0);
                }

                option_offset += option_len;
            }

            return ISC_R_SUCCESS;
        }

        if (!have_rr) {
            *first_rr_offset = rr_start;
            have_rr = true;
        }

        /* Store the RDLENGTH field offset for the last non-OPT RR. */
        *last_rr_offset = rdlength_index;
        msg_size = rr_end;
    }

    *body_size = msg_size - *body_offset;
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
    
 /*        // it is possible that one RR needs multiple fragments
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

