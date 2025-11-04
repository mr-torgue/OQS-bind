#include "include/dns/fragment.h"
#include <stdlib.h>
#include <isc/buffer.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>
#include <dns/fragment.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdatalist.h>
#include <dns/types.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>


// renders a fragment: meaning turning it from
// allocates MAXUDP bytes (usually 1232) 
static isc_result_t render_fragment(isc_mem_t *mctx, dns_message_t **messagep) {
    printf("Rendering...\n");
    REQUIRE((*messagep)->buffer == NULL); // otherwise it is already rendered
	REQUIRE((*messagep)->from_to_wire == DNS_MESSAGE_INTENTRENDER);

    // REQUIRE(..) // check if ready for rendering (do not know how...) 
    // dynamic allocation, so we can attach to the message
	isc_buffer_t *buffer = NULL;
    isc_buffer_allocate(mctx, &buffer, 4096);
	isc_result_t result;
	dns_message_t *message = *messagep;
	dns_compress_t cctx;

	message->from_to_wire = DNS_MESSAGE_INTENTRENDER;
	for (size_t i = 0; i < DNS_SECTION_MAX; i++) {
		message->counts[i] = 0;
	}

	dns_compress_init(&cctx, mctx, 0);

    printf("Render begin\n");
	REQUIRE(dns_message_renderbegin(message, &cctx, buffer) == ISC_R_SUCCESS);

    // always the same order
    unsigned options = DNS_MESSAGERENDER_ORDERED; // | DNS_MESSAGERENDER_PARTIAL;
    printf("Render question\n");
	REQUIRE(dns_message_rendersection(message, DNS_SECTION_QUESTION, 0) == ISC_R_SUCCESS);

    printf("Render answer\n");
    REQUIRE(dns_message_rendersection(message, DNS_SECTION_ANSWER, 0) == ISC_R_SUCCESS);

    printf("Render authority\n");
	REQUIRE(dns_message_rendersection(message, DNS_SECTION_AUTHORITY, 0) == ISC_R_SUCCESS);

    printf("Render additional\n");
	REQUIRE(dns_message_rendersection(message, DNS_SECTION_ADDITIONAL, 0) == ISC_R_SUCCESS);

    printf("Render end\n");
    message->flags &= ~DNS_MESSAGEFLAG_TC; // disable TC to trick renderend to render complete message
	dns_message_renderend(message);

	dns_compress_invalidate(&cctx);
    printf("Finished rendering...\n");
    printf("buffer length: %d\n", buffer->length);
    printf("buffer used: %d\n", buffer->used);
    message->buffer = buffer;
    dns_message_takebuffer(message, &buffer); // use buffer, the pointer will be set to NULL (message->buffer should still work)

    message->flags |= DNS_MESSAGEFLAG_TC; // quick fix: somehow the flag is not always set
    *(unsigned short *)(message->buffer->base + 1) |=  DNS_MESSAGEFLAG_TC; // buffer was not updated, so do it here
    return (result);

cleanup:
	dns_compress_invalidate(&cctx);
	return (result);
}


static void printmessage(isc_mem_t *mctx, dns_message_t *msg) {
	isc_buffer_t b;
	char *buf = NULL;
	int len = 1024;
	isc_result_t result = ISC_R_SUCCESS;

	do {
		buf = isc_mem_get(mctx, len);

		isc_buffer_init(&b, buf, len);
		result = dns_message_totext(msg, &dns_master_style_debug, 0,
					    &b);
		if (result == ISC_R_NOSPACE) {
			isc_mem_put(mctx, buf, len);
			len *= 2;
		} else if (result == ISC_R_SUCCESS) {
			printf("%.*s\n", (int)isc_buffer_usedlength(&b), buf);
		}
	} while (result == ISC_R_NOSPACE);

	if (buf != NULL) {
		isc_mem_put(mctx, buf, len);
	}
}


// TODO: remove mctx and use an array for name
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


// TODO: don't rely on the buffers to calculate size
unsigned calc_message_size(dns_message_t *msg,
    unsigned *num_sig_rr, unsigned *num_dnskey_rr, 
    unsigned *total_sig_rr, unsigned *total_dnskey_rr, unsigned *savings) {
    printf("Calculating message size...\n");
    REQUIRE(msg != NULL);
    REQUIRE(msg->saved.base != NULL || msg->buffer != NULL); // message size is based on either one of these fields
    // initalize values
    *num_sig_rr = 0;
    *num_dnskey_rr = 0;
    *total_sig_rr = 0;
    *total_dnskey_rr = 0;
    *savings = 0;
    
    dns_name_t *name = NULL;
    dns_rdataset_t *rdataset = NULL;

    unsigned rr_header_size = 10; // 2 (TYPE) + 2 (CLASS) + 4 (TTL) + 2 (RDLENGTH), excluding name
    unsigned msgsize;
    if (msg->saved.base != NULL) {
        msgsize = msg->saved.length;
    }
    else {
        msgsize = msg->buffer->used; // used instead of length
    }
    printf("msgsize: %u\n", msgsize);

    // we already have the total size, now we determine the amount of dnskeys/signatures
    // skip question section
    for(unsigned section = 1; section < DNS_SECTION_MAX; section++) {
        printf("Section %u with %u resource records...\n", section, msg->counts[section]);
        unsigned counter = 0;
        // go through each name, rdataset, and rdata item
        // for (dns_name_t *name = ISC_LIST_HEAD(msg->sections[section]); name != NULL; ISC_LIST_NEXT(name, link)) {
        for (isc_result_t result = dns_message_firstname(msg, section); result == ISC_R_SUCCESS;  result = dns_message_nextname(msg, section)) {
            name = NULL;
            dns_message_currentname(msg, section, &name);

            printf("name: %s\n", name->ndata);
            printf("name length: %d\n", name->length);
            if (name->length == 1 && dns_name_equal(name, dns_rootname)) {
                printf("This is the root domain (.).\n");
            }
            rr_header_size += name->length;
            
            for (rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                printf("Number of elements in rdataset: %u\n", dns_rdataset_count(rdataset));
                printf("rdataset type: %d\n", rdataset->type);
                isc_result_t tresult;
                for (tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
                    dns_rdata_t rdata = DNS_RDATA_INIT;
                    dns_rdataset_current(rdataset, &rdata);
                    unsigned rdata_size = rdata.length;
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

        // can be moved outside of this loop 
        // OPT record found!
        // only one allowed and can only be in the additional section
        if (msg->opt != NULL && section == DNS_SECTION_ADDITIONAL) {
            printf("Found an OPT message!\n");
            REQUIRE(dns_rdataset_count(msg->opt) == 1);
            counter++;
        }
        printf("Expected count: %u\nActual count: %u\n", msg->counts[section], counter);
        REQUIRE(msg->counts[section] == counter); // sanity check: msg->counts[i] and counter should be the same after this  (NOTE: this goes wrong with TSIG/SIG(0))
    }
    return msgsize;
}

unsigned estimate_message_size(dns_message_t *msg, unsigned *total_sig_bytes, unsigned *total_dnskey_bytes, unsigned *savings) {
    printf("Estimating message size...\n");
    unsigned rr_header_size = 10; // 2 (TYPE) + 2 (CLASS) + 4 (TTL) + 2 (RDLENGTH), excluding name
    unsigned msgsize = 0;
    // go through each section
    for(unsigned i = 0; i < DNS_SECTION_MAX; i++) {
        printf("Section %u\n", i);
	    unsigned rr_count = msg->counts[i];
        unsigned counter = 0;
        // go through each name, rdataset, and rdata item
        for (dns_name_t *name = ISC_LIST_HEAD(msg->sections[i]); name != NULL; ISC_LIST_NEXT(name, link)) {
            printf("Name %s\n", name->ndata);
            rr_header_size += name->length;
            for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                printf("Number of elements in rdataset: %u\n", dns_rdataset_count(rdataset));
                printf("rdataset type: %d\n", rdataset->type);
                for (isc_result_t tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
                    printf("Counter increased!\n");
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

// nr_fragments: the number of fragments to be used
// rdata_size: the size of the rdata in question
// can_send: amount of bytes that can be send in the current fragment
// total_pk_sig_bytes_per_frag: total amount of bytes that needs to be fragmented
//static void calculate_start_length(const unsigned nr_fragments, const unsigned rdata_size, const unsigned can_send, const unsigned total_pk_sig_bytes_per_frag, unsigned *start, unsigned *length) {
//    REQUIRE(*start < rdata_size);
//    unsigned rem_space_per_frag = can_send - total_pk_sig_bytes_per_frag;
//    unsigned num_bytes_to_send = rdata_size / nr_fragments;
//    *length = num_bytes_to_send +
//}

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
 
bool fragment(isc_mem_t *mctx, dns_message_t *msg, char *client_address) {
    printf("Fragmenting message...\n");
    REQUIRE(msg != NULL);
    REQUIRE(msg->counts[DNS_SECTION_QUESTION] == 1);
    REQUIRE(mctx != NULL);
    //msg->flags |= DNS_MESSAGEFLAG_TC; // quick fix: somehow the flag is not always set
    //REQUIRE(msg->flags & DNS_MESSAGEFLAG_TC); // truncated flag should be set
    unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
    // calculate message size
    msgsize = calc_message_size(msg, &nr_sig_rr, &nr_dnskey_rr, &total_size_sig_rr, &total_size_dnskey_rr, &savings);
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
    unsigned can_send_first_fragment, can_send_other_fragments, can_send;
    unsigned nr_fragments = get_nr_fragments(MAXUDP, msgsize, total_sig_pk_bytes, savings, &can_send_first_fragment, &can_send_other_fragments);
    printf("can_send (1st fragment): %u\n", can_send_first_fragment);
    printf("can_send (other fragments): %u\n", can_send_other_fragments);

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
        memset(offsets[section_nr], 0, msg->counts[section_nr] * sizeof(unsigned));
    }

    // create cache key
    unsigned char key[69];
    unsigned keysize = sizeof(key) / sizeof(key[0]);
    fcache_create_key(msg->id, client_address, key, &keysize);

    dns_name_t *name = NULL;
    // adding fragment to cache
    for (unsigned frag_nr = 0; frag_nr < nr_fragments; frag_nr++) {        
        printf("adding fragment %d to the fcache!\n", frag_nr + 1);
        //can_send = frag_nr == 0 ? can_send_first_fragment : can_send_other_fragments;
        //printf("Space for %u bytes!\n", can_send);
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
            printf("Section %u with %u resource records...\n", section_nr, msg->counts[section_nr]);
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
                        printf("new name: %s\n", new_name_str);
                        printf("%s\n", new_name->ndata);
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
                                // get start and length
                                calculate_start_end(frag_nr, nr_fragments, offsets[section_nr][counter], rdsize_no_header, can_send_first_fragment, can_send_other_fragments, total_sig_pk_bytes_per_frag, rr_pk_sig_count, &new_rdata_start, &new_rdata_length);
                                printf("Sending bytes %u to %u out of %u (header length: %u)\n", new_rdata_start, new_rdata_start + new_rdata_length, rdsize_no_header, header_size);

                                REQUIRE(new_rdata_start + new_rdata_length <= rdsize_no_header);
                                isc_buffer_t *buf = NULL;
                                isc_buffer_allocate(mctx, &buf, new_rdata_length + header_size); // allocate
                                isc_buffer_putmem(buf, rdata_region.base, header_size); // copy rdata header
                                isc_buffer_putmem(buf, rdata_region.base + header_size + new_rdata_start, new_rdata_length); // copy rdata data
                                isc_buffer_usedregion(buf, &new_rdata_region); 
                                dns_rdata_fromregion(new_rdata, rdata.rdclass, rdata.type, &new_rdata_region); // create new rdata
                                printf("new_rdata_region.length: %u\n", new_rdata_region.length);
                                REQUIRE(new_rdata_region.length == new_rdata_length + header_size);
                                dns_message_takebuffer(msg, &buf);
                                ISC_LIST_APPEND(rdatalist->rdata, new_rdata, link); // append to list
                                new_section_count++;
                                offsets[section_nr][counter] = new_rdata_start + new_rdata_length;
                            }
                            else if (frag_nr == 0) {
                                isc_buffer_t *buf = NULL;
                                isc_buffer_allocate(mctx, &buf, rdata_region.length); // allocate
                                isc_buffer_putmem(buf, rdata_region.base, rdata_region.length); // copy rdata
                                isc_buffer_usedregion(buf, &new_rdata_region); 
                                dns_rdata_fromregion(new_rdata, rdata.rdclass, rdata.type, &new_rdata_region); // create new rdata
                                printf("new_rdata_region.length: %u\n", new_rdata_region.length);
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
                    // check if not empty??
                    if (new_section_count > 0) {
                        printf("Adding new name %s for section %u...\n", new_name->ndata, section_nr);
                        dns_message_addname(frag, new_name, section_nr);
                    }
                }
            }
            // can be moved, but leads to sanity check issues
            // OPT record found!
            // only one allowed and can only be in the additional section
            if (msg->opt != NULL && section_nr == DNS_SECTION_ADDITIONAL) {
                printf("Found an OPT message!\n");
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
                isc_region_t new_opt_rdata_region;
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
            printf("Expected count: %u\nActual count: %u\n", msg->counts[section_nr], counter);

            REQUIRE(counter == msg->counts[section_nr]); 
            printf("New section count: %u\n", new_section_count);
            frag->counts[section_nr] = new_section_count;
        }
        printf("Adding Fragment %d to cache...\n", frag_nr);
	    REQUIRE(DNS_MESSAGE_VALID(frag));
        //render_message(mctx, &msg);
        render_fragment(mctx, &frag);
        //printmessage(mctx, frag);
        fcache_add(key, keysize, frag, nr_fragments);
        dns_message_detach(&frag);
    }

    // free memory
    for (unsigned section_nr = 0; section_nr < DNS_SECTION_MAX; section_nr++) {
        isc_mem_put(mctx, offsets[section_nr], msg->counts[section_nr] * sizeof(unsigned));
    }
    isc_mem_put(mctx, offsets, DNS_SECTION_MAX * sizeof(unsigned *));

    return true;

}

// reassembles the complete message from cache
// assumption: cache contains all fragments
// assumption: size of fragments should add up to size specified in entry
bool reassemble_fragments(isc_mem_t *mctx, fragment_cache_entry_t *entry, dns_message_t **out_msg) {
    printf("Reassembling entry %s...\n", entry->key);
    REQUIRE(out_msg != NULL && *out_msg == NULL);

    // check if all fragments are in cache
    if (entry->bitmap != (1 << entry->nr_fragments) - 1) {
        fprintf(stderr, "Not all fragments have been received for entry %s (bitmap: %x)", entry->key, entry->bitmap);
        return false;
    }

    // create new message
    //dns_message_t *tmp_msg = NULL;
    dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, out_msg);

    // copy first fragment
    //isc_buffer_t *msg_buf = NULL;
    //isc_buffer_dup(mctx, &msg_buf, entry->fragments[0]);
    dns_message_parse(*out_msg, entry->fragments[0], 0); // create first fragment message

    // first fragment is already copied
    for(unsigned frag_nr = 1; frag_nr < entry->nr_fragments; frag_nr++) {
        printf("Combinging fragment %u out of %u...\n", frag_nr, entry->nr_fragments);
        dns_message_t *frag = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &frag);
        dns_message_parse(frag, entry->fragments[frag_nr], 0);

        // we build a new message everytime
        //dns_message_t *builder = NULL;
        //dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &builder);

        for(unsigned section = 1; section < DNS_SECTION_MAX; section++) {
            printf("Adding section %u...\n", section);
            // set msg pointer to first name, first rrset, first rr
            // I think this should always work...
            isc_result_t result_msg = dns_message_firstname(*out_msg, section);
            
            // possible. for example OPT record is not stored in the main dns message structure
            if(frag->counts[section] > 0 && result_msg == ISC_R_SUCCESS) {
                printf("Adding %u resource records...\n", frag->counts[section]);
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
                    printf("Name %s...\n", name_frag->ndata);

                    for (dns_rdataset_t *rdataset_frag = ISC_LIST_HEAD(name_frag->list); rdataset_frag != NULL; rdataset_frag = ISC_LIST_NEXT(rdataset_frag, link)) {
                        printf("Using new rdataset (%u)...\n", rdataset_frag->type);
                        for (isc_result_t tresult_frag = dns_rdataset_first(rdataset_frag); tresult_frag == ISC_R_SUCCESS; tresult_frag = dns_rdataset_next(rdataset_frag)) {
                            dns_rdata_t rdata_frag = DNS_RDATA_INIT;
                            dns_rdataset_current(rdataset_frag, &rdata_frag);
                            printf("Using new rdata (%u)...\n", rdata_frag.type);

                            // find matching resource record in the message
                            while (result_msg == ISC_R_SUCCESS) {
                                name_msg = NULL;
                                dns_message_currentname(*out_msg, section, &name_msg);
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
                                    tresult_msg = dns_rdataset_first(rdataset_msg); // reset to first rdata
                                }
                                result_msg = dns_message_nextname(*out_msg, section); 
                                rdataset_msg = ISC_LIST_HEAD(name_msg->list); // reset to first rdataset 
                                tresult_msg = dns_rdataset_first(rdataset_msg); // reset to first rdata
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
    // would be slightly more efficient to do this in the loop
    fcache_remove(entry->key, entry->keysize);
    (*out_msg)->from_to_wire = DNS_MESSAGE_INTENTRENDER;
    render_fragment(mctx, out_msg);
    return true;
}
