#pragma once 

#include <string.h>
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/types.h>

// key = id + client ip:port
// overwrites keysize to match the string length
static void fcache_create_key(dns_messageid_t id, char *client_address, unsigned char *key, unsigned *keysize) {
    REQUIRE(*keysize >= 64);
    int tmp = snprintf((char *)key, *keysize, "%x-%s", id, client_address);
    *keysize = tmp > 0 ? (unsigned)tmp : *keysize; // set keysize to string length
}

// DNSKEY header: 2 (Flags) + 1 (Protocol) + 1 (Algorithm) = 4 Bytes
static unsigned calc_dnskey_header_size(void) {
    return 4;
}

// RRSIG header: 2 (Type Covered) + 1 (Algorithm) + 1 (Labels) + 4 (TTL) + 4 (Expiration) + 4 (Inception) + 2 (Key Tag) + x (Signer Name) = 18 + x
static unsigned calc_rrsig_header_size(dns_rdata_t *rdata) {
    unsigned header_size = 18;  
    //signer's name length is variable
    while (rdata->data[header_size] != 0 && header_size < rdata->length) {
        header_size++;
    }
    return ++header_size;
}

// create a query from a given buffer that represents a dns message
// returns true if a query was created
// NOTE: can be optimized (e.g. remove parsing):
// 1. peek at header to determine flags and id
// 2. peek at query/question to get name
// 3. construct question section 
// 4. construct OPT --> use default values
static bool get_fragment_query_raw(isc_mem_t *mctx, isc_buffer_t *buffer, uint fragment_nr, dns_message_t **question, isc_buffer_t **question_buffer) {
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