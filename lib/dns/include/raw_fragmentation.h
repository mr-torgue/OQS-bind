/*
raw fragmentation fragments the complete UDP message.
the flow works as follows:
1. Oversize DNS Response generated
2. Nr of fragments calculated based on body size (e.g. 4000 bytes of data needs 4 fragments)
3. First fragment will carry an OPT record specifying:
    a. number of fragments (1 byte)
4. Resolver will query for the remaining fragments using ?frag_nr?[domain] (no OPT record)
5. Once all fragments have been received, resolver will recombine

Advantages:
1. No need
*/

recombine:
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