#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>
#include <dns/fragment_helpers.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>

void fcache_create_key(dns_messageid_t id, char *client_address, unsigned char *key, unsigned *keysize) {
    REQUIRE(*keysize >= 64);
    int tmp = snprintf((char *)key, *keysize, "%x-%s", id, client_address);
    *keysize = tmp > 0 ? (unsigned)tmp : *keysize; // set keysize to string length
}

unsigned calc_dnskey_header_size(void) {
    return 4;
}

unsigned calc_name_size(unsigned char *base, unsigned length) {
    unsigned size = 0;
    while (base[size] != 0 && size < length) {
        size++;
    }    
    return size;
}

unsigned calc_rrsig_header_size(dns_rdata_t *rdata) {
    unsigned header_size = 18;  
    //signer's name length is variable
    while (rdata->data[header_size] != 0 && header_size < rdata->length) {
        header_size++;
    }
    return ++header_size;
}

void printmessage(isc_mem_t *mctx, dns_message_t *msg) {
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

// clones a complete section from source to target
isc_result_t section_clone(dns_message_t *source, dns_message_t *target, const unsigned section) {
    REQUIRE(section < DNS_SECTION_MAX);
    REQUIRE(DNS_MESSAGE_VALID(source));
    REQUIRE(DNS_MESSAGE_VALID(target));
    isc_result_t ret = ISC_R_SUCCESS;
    for (isc_result_t result = dns_message_firstname(source, section); 
         result == ISC_R_SUCCESS;  
         result = dns_message_nextname(source, section)) {
        // clone name (shallow)
        dns_name_t *name = NULL;
        dns_message_currentname(source, section, &name);
        dns_name_t *new_name = NULL;
        dns_message_gettempname(target, &new_name);
        dns_name_clone(name, new_name);
        // clone all rdatasets
        for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
            dns_rdataset_t *new_rdataset = NULL;
            dns_message_gettemprdataset(target, &new_rdataset);
            dns_rdataset_clone(rdataset, new_rdataset);
            // clone all rdata's
            for (isc_result_t tresult = dns_rdataset_first(rdataset); tresult == ISC_R_SUCCESS; tresult = dns_rdataset_next(rdataset)) {
                dns_rdata_t rdata = DNS_RDATA_INIT;
                dns_rdataset_current(rdataset, &rdata);
                dns_rdata_t *new_rdata = NULL;
                dns_message_gettemprdata(target, &new_rdata);
                dns_rdata_clone(&rdata, new_rdata);
                ISC_LIST_APPEND(new_rdataset->rdlist.list->rdata, new_rdata, link); // append to list
            }
            ISC_LIST_APPEND(new_name->list, new_rdataset, link);
        }
        dns_message_addname(target, new_name, section);
    }
    // clone OPT if in the additional section
    if (source->opt != NULL && section == DNS_SECTION_ADDITIONAL) {
        REQUIRE(dns_rdataset_count(source->opt) == 1);
        dns_rdataset_t *new_opt_rdataset = NULL;
        dns_message_gettemprdataset(target, &new_opt_rdataset);    
        dns_rdataset_clone(source->opt, new_opt_rdataset);
        ret = dns_message_setopt(target, new_opt_rdataset);
    }
    return ret;
}

bool get_fragment_query_raw(isc_mem_t *mctx, isc_buffer_t *buffer, uint fragment_nr, dns_message_t **question, isc_buffer_t **question_buffer) {
    REQUIRE(question != NULL && *question == NULL);
    REQUIRE(question_buffer != NULL && *question_buffer == NULL);

    bool res = false;

    // parse buffer into dns_message_t
    dns_message_t *msg = NULL;
    dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
    isc_buffer_first(buffer); // start from 0
    isc_result_t result = dns_message_parse(msg, buffer, 0);
    if(result == ISC_R_SUCCESS) {
        // get question
        dns_name_t *orig_name = NULL;
        result = dns_message_firstname(msg, DNS_SECTION_QUESTION);
        if(result == ISC_R_SUCCESS) {
            dns_message_currentname(msg, DNS_SECTION_QUESTION, &orig_name);
            char *name_str = NULL;
            dns_name_tostring(orig_name, &name_str, mctx);
            char new_name_str[128];
            snprintf(new_name_str, 128, "?%u?%s", fragment_nr, name_str);

            // get first rdataset
            dns_rdataset_t *rdataset = ISC_LIST_HEAD(orig_name->list);
            REQUIRE(rdataset != NULL);

            // set up question
            dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, question);
            dns_name_t *qname = NULL;
            dns_rdataset_t *qrdataset = NULL;
            
            dns_message_gettempname(*question, &qname);
            dns_message_gettemprdataset(*question, &qrdataset);
            dns_name_fromstring(qname, new_name_str, NULL, 0, mctx);
            dns_rdataset_makequestion(qrdataset, rdataset->rdclass, rdataset->type);
            ISC_LIST_APPEND(qname->list, qrdataset, link); 

            // add name and set id
            //dns_messageid_t id;
            // unsigned flags;
            dns_message_addname(*question, qname, DNS_SECTION_QUESTION);
            //dns_message_peekheader(buffer, &id, &flags);
            (*question)->id = msg->id;
            
            // set opt
            if (msg->opt != NULL) {
                REQUIRE(dns_rdataset_count(msg->opt) == 1);
                dns_rdataset_t *new_opt_rdataset = NULL;
                dns_message_gettemprdataset(*question, &new_opt_rdataset);

                // get first rdata from msg->opt
                REQUIRE(dns_rdataset_first(msg->opt) == ISC_R_SUCCESS); // there should be one resource record
                dns_rdata_t rdata = DNS_RDATA_INIT;
                dns_rdataset_current(msg->opt, &rdata);
                isc_region_t rdata_region;
                dns_rdata_toregion(&rdata, &rdata_region);

                // prepare new rdata
                dns_rdata_t *new_opt_rdata = NULL;
                dns_message_gettemprdata(*question, &new_opt_rdata);
                isc_region_t new_opt_rdata_region;
                dns_rdata_fromregion(new_opt_rdata, rdata.rdclass, rdata.type, &rdata_region); 

                // add to new rdataset
                dns_rdatalist_t *rdatalist = NULL;
                dns_message_gettemprdatalist(*question, &rdatalist);
                ISC_LIST_APPEND(rdatalist->rdata, new_opt_rdata, link);
                // copy values
                rdatalist->rdclass = msg->opt->rdclass;
                rdatalist->type = msg->opt->type;
                rdatalist->ttl = msg->opt->ttl; 
                dns_rdatalist_tordataset(rdatalist, new_opt_rdataset);
                REQUIRE(dns_message_setopt(*question, new_opt_rdataset) == ISC_R_SUCCESS);
            }
            
            // parsing: only question and additional
            dns_compress_t cctx;
            isc_buffer_allocate(mctx, question_buffer, 1232); // no need to allocate more
            dns_compress_init(&cctx, mctx, 0);
            REQUIRE(dns_message_renderbegin(*question, &cctx, *question_buffer) == ISC_R_SUCCESS);
	        REQUIRE(dns_message_rendersection(*question, DNS_SECTION_QUESTION, 0) == ISC_R_SUCCESS);
	        REQUIRE(dns_message_rendersection(*question, DNS_SECTION_ADDITIONAL, 0) == ISC_R_SUCCESS);
            REQUIRE(dns_message_renderend(*question) == ISC_R_SUCCESS);
	        dns_compress_invalidate(&cctx);

            // free memory
            isc_mem_free(mctx, name_str);

            res = true;
        }   
        else {
            fprintf(stderr, "Could not find name in QUESTION section...\n");
        }
    }
    else {
        fprintf(stderr, "Could not convert buffer into question...\n");
    }
    dns_message_detach(&msg);
    return res;
}

isc_result_t render_fragment(isc_mem_t *mctx, unsigned msg_size, dns_message_t **messagep) {
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
        "Rendering message %u with buffer size %u", (*messagep)->id, msg_size); 
    // if already rendered
    if ((*messagep)->buffer != NULL) {
        return ISC_R_EXISTS;
    }

    // REQUIRE(..) // check if ready for rendering (do not know how...) 
    // dynamic allocation, so we can attach to the message
	isc_buffer_t *buffer = NULL;
    isc_buffer_allocate(mctx, &buffer, msg_size);
	isc_result_t result = ISC_R_SUCCESS;
	dns_message_t *message = *messagep;
	dns_compress_t cctx;

	message->from_to_wire = DNS_MESSAGE_INTENTRENDER;
	for (size_t i = 0; i < DNS_SECTION_MAX; i++) {
		message->counts[i] = 0;
	}

	dns_compress_init(&cctx, mctx, 0);

	REQUIRE(dns_message_renderbegin(message, &cctx, buffer) == ISC_R_SUCCESS);

    // always the same order
    unsigned options = 0; //DNS_MESSAGERENDER_ORDERED; 
    result = dns_message_rendersection(message, DNS_SECTION_QUESTION, options);
    if (result != ISC_R_SUCCESS) {
        printf("Could not render DNS_SECTION_QUESTION section, result: %d, buffer size: %u!\n", result, msg_size);
        return result;
    }
    result = dns_message_rendersection(message, DNS_SECTION_ANSWER, options);
    if (result != ISC_R_SUCCESS) {
        printf("Could not render DNS_SECTION_ANSWER section, result: %d, buffer size: %u!\n", result, msg_size);
        return result;
    }
    result = dns_message_rendersection(message, DNS_SECTION_AUTHORITY, options);
    if (result != ISC_R_SUCCESS) {
        printf("Could not render DNS_SECTION_AUTHORITY section, result: %d, buffer size: %u!\n", result, msg_size);
        return result;
    }
    result = dns_message_rendersection(message, DNS_SECTION_ADDITIONAL, options);
    if (result != ISC_R_SUCCESS) {
        printf("Could not render DNS_SECTION_ADDITIONAL section, result: %d, buffer size: %u!\n", result, msg_size);
        return result;
    }
    message->flags &= ~DNS_MESSAGEFLAG_TC; // disable TC to trick renderend to render complete message
	REQUIRE(dns_message_renderend(message) == ISC_R_SUCCESS);

	dns_compress_invalidate(&cctx);
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FRAGMENT, ISC_LOG_DEBUG(8),
        "Finished rendering, stored %u bytes in msg->buffer", buffer->used); 
    message->buffer = buffer;
    dns_message_takebuffer(message, &buffer); // use buffer, the pointer will be set to NULL (message->buffer should still work)

    message->flags |= DNS_MESSAGEFLAG_TC; // quick fix: somehow the flag is not always set
    *(unsigned short *)(message->buffer->base + 1) |=  DNS_MESSAGEFLAG_TC; // buffer was not updated, so do it here
    return (result);
}