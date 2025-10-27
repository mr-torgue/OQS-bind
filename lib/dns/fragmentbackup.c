#include <isc/util.h>
#include <dns/fragment.h>

// key = id + client ip:port
static void fcache_create_key(dns_messageid_t id, char *client_address,unsigned client_address_size, unsigned char *buffer, unsigned bufsize) {
    REQUIRE(bufsize >= sizeof(id) + client_address_size);
    memcpy(buffer, &id, sizeof(id));
    memcpy(buffer + sizeof(id), &client_address, client_address_size);
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


int size_section(dns_namelist_t *section, const unsigned count, 
                 unsigned *num_sig_rr, unsigned *num_dnskey_rr, 
                 unsigned *total_sig_rr, unsigned *total_dnskey_rr, unsigned *savings) {
    size_t size = 0;
    int alg_sig_size, alg_pk_size;
    for (dns_rdataset_t *rdataset = ISC_LIST_HEAD(answer_section->list);
         rdataset != NULL; rdataset = ISC_LIST_NEXT(rdataset, link)) {
                for (dns_rdata_t *rdata = ISC_LIST_HEAD(rdataset->rdata);
                     rdata != NULL;
                     rdata = ISC_LIST_NEXT(rdata, link)) {
                    size_t rr_size = 0;
                    size_t rr_outlen;
                    if (rdataset->type == RRSIG) {
                        printf("\nRRSIG RR found...");
                        *num_sig_rr += 1;
                        rdataset->
                    }
                    else if (rdataset->type == DNSKEY) {
                        printf("\nDNSKEY RR found...");
                        *num_dnskey_rr += 1;
                    }
                    else {

                    }    
                }
            }
        }
    }
    for (int i = 0; i < count; i++) {
        // keeps track of the rr_size
        size_t rr_size = 0;
        size_t rr_outlen;
        unsigned char *rrout;
        ResourceRecord *rr = section[i];
        rr_to_bytes(rr, &rrout, &rr_outlen);

        // if resolver, calculate total message size based on known key sizes
        // NOTE: can be slightly of because of variable signature/key size
        // TODO: fix for production
        if (rr->type == RRSIG) {
            printf("\nRRSIG RR found...");
            *num_sig_rr += 1;
            int num_sig_frag_bytes = calc_num_sig_bytes(rr->rdsize, rr->rdata);
            printf("\nnum_sig_bytes: %d", num_sig_frag_bytes);
            if (is_resolver) {
                alg_sig_size = get_alg_sig_pk_size(rr->type, rr->rdata);
                rr_size = rr_outlen - num_sig_frag_bytes + alg_sig_size;
                // use alg_sig_size as estimate
                sizes[i] = alg_sig_size;
                *total_sig_rr += alg_sig_size;
            }
            else {
                rr_size = rr_outlen;
                // complete message so use this
                sizes[i] = num_sig_frag_bytes;
                *total_sig_rr += num_sig_frag_bytes;
            }
        } 
        else if (rr->type == DNSKEY && (rr->rdata[3] != SPHINCS_PLUS_SHA256_128S_ALG)) {
            printf("\nDNSKEY RR found...");
            *num_dnskey_rr += 1;
            // | Flags (2B) | Protocol (1B) | Algorithm (1B) | Key |
            int header_size = 4;
            int num_dnskey_frag_bytes = rr->rdsize - header_size;
            printf("\nnum_dnskey_bytes: %d", num_dnskey_frag_bytes);
            if (is_resolver) {
                alg_pk_size = get_alg_sig_pk_size(rr->type, rr->rdata);
                rr_size = rr_outlen - num_dnskey_frag_bytes + alg_pk_size;                
                // use alg_sig_size as estimate
                sizes[i] = alg_pk_size;
                *total_sig_rr += alg_pk_size;
            }
            else {
                rr_size = rr_outlen;
                // gets ignored for resolvers
                sizes[i] = num_dnskey_frag_bytes;
                *total_dnskey_rr += num_dnskey_frag_bytes;
            }
        } 
        else {
            rr_size = rr_outlen;
            if (!is_additional || rr->type != OPT)
                *savings += rr_outlen;
            // should not get used but store just in case
            sizes[i] = rr_size;
        }
        printf("\nAnswer %d size: %ld", i, rr_outlen);
        size += rr_size;
    }
    return size;
}

bool calc_message_size(dns_message_t *msg, unsigned *msg_size, 
                       unsigned *section_sizes, unsigned nr_sections,
                       unsigned *answer_sizes, unsigned *authoritative_sizes, unsigned *additional_sizes, 
                       unsigned *num_sig_rr, unsigned *num_dnskey_rr, 
                       unsigned *total_sig_rr, unsigned *total_dnskey_rr, unsigned *savings) {
    REQUIRE(nr_sections == DNS_SECTION_MAX);
    // get counts
    unsigned question_count = message->counts[DNS_SECTION_QUESTION];
    unsigned answer_count = message->counts[DNS_SECTION_ANSWER];
    unsigned authority_count = message->counts[DNS_SECTION_AUTHORITY];
    unsigned additional_count = message->counts[DNS_SECTION_ADDITIONAL];
    *msg_size = msg->buffer->used;
    for(unsigned i = 0; i < DNS_SECTION_MAX; i++) {
        section_sizes[i] = msg->sections
    }

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


bool fragment(const dns_messaget_t *msg) {
    int num_dnskey_rr = 0;
    int num_sig_rr = 0;
    int total_sig_rr = 0;
    int total_dnskey_rr = 0;
    int savings = 0; // space taken by redundant RRs

    // store rr sizes for each section
    unsigned section_sizes[DNS_SECTION_MAX];

    // calculate message size
    size_t msgsize = calc_message_size(msg, &section_sizes, &num_sig_rr, &num_dnskey_rr, &total_sig_rr, &total_dnskey_rr, &savings);

    // print information
    printf("Total DNS Message size: %ld\n", msgsize);
    printf("nr. sig: %d, total size: %d\n", num_sig_rr, total_sig_rr);
    printf("nr. keys: %d, total size: %d\n", num_dnskey_rr, total_dnskey_rr);
    int total_sig_pk_bytes = total_sig_rr + total_dnskey_rr;
    int rr_pk_sig_count = num_sig_rr + num_dnskey_rr;
    printf("total_sig_pk_bytes: %d\n", total_sig_pk_bytes);
    printf("MAXUDP: %d\n", MAXUDP);
    printf("Savings: %d\n", savings);

    // calculate nr of fragments
    int can_send_first_fragment, can_send;
    int num_required_frags = calculate_fragments(msgsize, total_sig_pk_bytes, savings, &can_send_first_fragment, &can_send);
    printf("\nnum_required_frags: %d", num_required_frags);  
    printf("\ncan_send (1st frag): %d", can_send_1);
    printf("\ncan_send (rest frags): %d", can_send);

    // what happens if not divisible?
    // calculate bytes per fragment
    int num_sig_bytes_per_frag = total_sig_rr / num_required_frags;
    printf("\nnum_sig_bytes_per_frag: %d", num_sig_bytes_per_frag);
    int num_pk_bytes_per_frag = total_dnskey_rr / num_required_frags;
    printf("\nnum_pk_bytes_per_frag: %d", num_pk_bytes_per_frag);
    int total_sig_pk_bytes_per_frag = num_sig_bytes_per_frag + num_pk_bytes_per_frag;


    for (int i = 0; i <= num_required_frags; i++) {
        printf("\n\nFragment %d", i);
        printf("\nFragmenting DNS Message....");

        dns_message_t *frag = NULL;
        // copy question
        for (unsigned section = DNS_SECTION_ANSWER; section < DNS_SECTION_MAX; section++) {
            fragment_section()
        } 
    }

        uintptr_t out;
        ResponderMsgStore *store = malloc(sizeof(ResponderMsgStore));
        uint16_t *id = malloc(sizeof(uint16_t));
        *id = msg->identification;

        if (!hashmap_get(responder_state, id, sizeof(uint16_t), &out)) {
            printf("\nAdding full msg to cache...");
            clone_dnsmessage(msg, &(store->m_arr[0]));
            store->num_required_frags = num_required_frags;
        }

        for (int i = 1; i <= num_required_frags; i++) {

            printf("\n\nFragment %d", i);
            printf("\nFragmenting DNS Message....");

            int savings = 0;

            DNSMessage *m;
            clone_dnsmessage(msg, &m);

            // are these records freed?
            Question **question_section = malloc(sizeof(Question * ) * msg->qdcount);
            memcpy(question_section, msg->question_section, sizeof(Question * ) * msg->qdcount);
            ResourceRecord **answers_section = malloc(sizeof(ResourceRecord * ) * m->ancount);
            ResourceRecord **authoritative_section = malloc(sizeof(ResourceRecord * ) * m->nscount);
            ResourceRecord **additional_section = malloc(sizeof(ResourceRecord * ) * m->arcount);

            uint16_t qdcount = m->qdcount;
            uint16_t ancount = create_fragments(m->answers_section, answers_section, m->ancount, i, num_required_frags, answer_sizes, can_send_1, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, false, &savings);
            uint16_t nscount = create_fragments(m->authoritative_section, authoritative_section, m->nscount, i, num_required_frags, authoritative_sizes, can_send_1, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, false, &savings);   
            uint16_t arcount = create_fragments(m->additional_section, additional_section, m->arcount, i, num_required_frags, additional_sizes, can_send_1, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, true, &savings);

            printf("\nSavings: %d", savings);
            printf("\nAdding Fragment %d to cache...\n", i);
            m->flags = m->flags | (1 << 9);    // Mark as Truncated
            DNSMessage *tmp;
            create_dnsmessage(&tmp, m->identification, m->flags, qdcount, ancount, nscount, arcount,
                            question_section, answers_section, authoritative_section, additional_section);
            clone_dnsmessage(tmp, &(store->m_arr[i]));
            destroy_dnsmessage(&m);
            destroy_dnsmessage(&tmp);
        }
        // using just ID as key is ok for POC but not for deployment
        hashmap_set(responder_state, id, sizeof(uint16_t), (uintptr_t) store);
        // free up memory
        // free(id);
        free(answer_sizes);
        free(authoritative_sizes);
        free(additional_sizes);
    }
    return num_required_frags;

}

bool fragment(dns_message_t *msg) {
    unsigned nr_fragments = get_nr_fragments(msg);
    if (nr_fragments == 1) {
        fprintf(stderr, "DNSMessage does not need UDP fragmentation!\n");
        return false;
    }

    // adding fragment to cache
    for (unsigned i = 0; i < nr_fragments; i++) {
        printf("adding fragment %d to the fcache!\n", i);
        dns_message_t *frag;
        unsigned char *key;
        unsigned int keysize;
        fcache_add(key, keysize, frag, nr_fragments);
    }
    
    // change first fragment so it fits in one packet

    return true;

}


// reassembles the complete message from cache
// assumption: cache contains all fragments
// assumption: size of fragments should add up to size specified in entry
static bool reassemble_fragments(fragment_cache_entry_t *entry, dns_message_t *out_msg) {
    REQUIRE(entry->bitmap == ~0);
    isc_buffer_t *msg_buf;
    isc_buffer_allocate(frag_mctx, &msg_buf, entry->size);
    unsigned offset = 0;
    for(unsigned i = 0; i < entry->nr_fragments; i++) {
        isc_region_t region;
        region.base = entry->fragments[i]->base;
        region.length = entry->fragments[i]->used;
        isc_buffer_copyregion(msg_buf + offset, &region);
        offset += entry->fragments[i]->used;
    }
    REQUIRE(offset == entry->size);
    // set ignore TC flag
    unsigned options = DNS_MESSAGEPARSE_IGNORETRUNCATION;
    dns_message_parse(out_msg, msg_buf, options);
}
/*
// callback function for received fragments
static void frag_cb(dns_request_t *request, isc_result_t result, dns_message_t *response, void *arg)  {
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
            }
        }
        else {
            printf("No entry for key %s in fragment cache!", key);
        }
    }
    else {
        printf("Request failed: %s\n", isc_result_totext(result));
    }
}


//This function is triggered on the first fragment it receives (resolver)
bool request_fragments(resquery_t *query,) {
    unsigned nr_fragments = get_nr_fragments(frag);
    printf("Adding first fragment to cache...");
    add_to_cache(dns_message_t *msg, dns_cache_t *cache);
    printf("Requesting %d additional fragments...", nr_fragments - 1);
    for (int i = 2; i <= nr_fragments; i++) {
        dns_request_t *request = NULL;
        // copy requst

        dns_request_create(
            &request,
            dns_rdataclass_in,
            dns_rdatatype_a,
            "example.com",
            query_callback,
            NULL,
            NULL,
            NULL,
            NULL,
            0,
            NULL,
            NULL,
            &cb,
            msg->id,
            0
        );
        // Send the request
        dns_request_send(&request);
    }
}
*/