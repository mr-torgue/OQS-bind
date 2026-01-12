/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>
#include <time.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/types.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/managers.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/thread.h>
#include <isc/urcu.h>
#include <isc/util.h>
#include <isc/uv.h>


#include <dns/udp_fragmentation.h>
#include <dns/qbf.h>
#include <dns/types.h>
#include <dns/fcache.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/fixedname.h>

#include <tests/dns.h>

// global variables so the teardown function can deallocate
static dns_message_t *msg = NULL;
unsigned char *buffer = NULL;
size_t buffer_size;
static unsigned max_udp_size = 1232;

static int
setup_test(void **state) {
	setup_loopmgr(state);

	return (0);
}

static int
teardown_test(void **state) {
    printf("Tear it down!\n");
	teardown_loopmgr(state);
    if(msg != NULL) {
        dns_message_detach(&msg);
    }
    if(buffer != NULL) {
        isc_mem_put(mctx, buffer, buffer_size);
    }
	return (0);
}

static unsigned char* load_binary_file(const char* filename, size_t* out_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    // get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size < 0) {
        perror("Failed to get file size");
        fclose(file);
        return NULL;
    }

    fprintf(stderr, "file_size: %ld\n", file_size);
    unsigned char* buffer = (unsigned char*)isc_mem_get(mctx, file_size);
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(file);
        return NULL;
    }
    size_t bytes_read = fread(buffer, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        perror("Failed to read file");
        isc_mem_put(mctx, buffer, file_size);
        fclose(file);
        return NULL;
    }

    fclose(file);
    *out_size = file_size;
    return buffer;
}

// print a buffer
static void printbuffer(unsigned char *buffer, size_t buffer_size) {
    printf("buffer: ");
    for(unsigned i = 0; i < buffer_size; i++) {
        printf("%X ", buffer[i]);
    }
    printf("\n");
}


ISC_RUN_TEST_IMPL(calculate_start_end_test) {
    // test case 1 (based on dilithium2)
    unsigned frag_nr = 0;
    unsigned nr_fragments = 7;
    unsigned msgsize = 7468;
    unsigned rdsize_no_header = 2420;
    unsigned rr_pk_sig_count = 3;
    unsigned sigpkbytes = 7260;
    unsigned sigpkbytes_frag = sigpkbytes / nr_fragments;
    unsigned savings = 161;
    unsigned can_send_first_fragment = 1024;
    unsigned can_send_other_fragments =  1181;
    unsigned offset = 0;
    unsigned start, len;
    //calculate_start_end(frag_nr, nr_fragments, offset, rdsize_no_header, can_send_first_fragment, can_send_other_fragments, sigpkbytes_frag, rr_pk_sig_count, &start, &len);
    //printf("start: %u, len: %u\n", start, len);
    //assert_int_equal(start, 0);
    for (unsigned i = 0; i < nr_fragments; i++) {
        double remainder = 0;
        unsigned used_bytes = 0;
        calculate_start_end(i, nr_fragments, offset, rdsize_no_header, can_send_first_fragment, can_send_other_fragments, sigpkbytes, &start, &len, &remainder, &used_bytes);
        offset = start + len;
        //printf("start: %u, len: %u\n", start, len);
        if (i == 0) {
            assert_true(used_bytes <= can_send_first_fragment);
        }
        else {
            assert_true(used_bytes <= can_send_other_fragments);
        }
    }
}

ISC_RUN_TEST_IMPL(get_nr_fragments_test) {
    unsigned max_msg_size, total_msg_size, total_sig_pk_bytes, savings, can_send_first_msg, can_send, result;
    result = get_nr_fragments(1232, 1100, 900, 0, &can_send_first_msg, &can_send);
    assert_int_equal(result, 1);
    result = get_nr_fragments(1232, 1300, 900, 0, &can_send_first_msg, &can_send);
    assert_int_equal(result, 2);
    assert_int_equal(can_send_first_msg, 832); // 1300 - 900 = 400 of static bytes, 1232 - 400 = 832 that can be send in the first fragment
    assert_int_equal(can_send, 828); // 832 + savings (0) - 4 = 828
    result = get_nr_fragments(1232, 2500, 1900, 130, &can_send_first_msg, &can_send);
    assert_int_equal(result, 3);
    assert_int_equal(can_send_first_msg, 632); // 2500 - 1900 = 600 of static bytes, 1232 - 600 = 632 that can be send in the first fragment
    assert_int_equal(can_send, 758); // 632 + 130 - 4 = 758
}

ISC_RUN_TEST_IMPL(calc_message_size_test) {
    const char *filename = "testdata/message/response1-falcon512";
    const char *src_address = "1.2.3.4";
    buffer = load_binary_file(filename, &buffer_size);

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        //isc_buffer_printf(&buf, "aa");
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);

        // main test
        unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
        unsigned count[DNS_SECTION_MAX] = {0};
        msgsize = calc_message_size(msg, &nr_sig_rr, &nr_dnskey_rr, &total_size_sig_rr, &total_size_dnskey_rr, &savings, count, DNS_SECTION_MAX);
        assert_int_equal(msgsize, 3244);
        assert_int_equal(nr_sig_rr, 2);
        assert_int_equal(nr_dnskey_rr, 2);
        assert_int_equal(total_size_sig_rr, 1332);
        assert_int_equal(total_size_dnskey_rr, 1794);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }

    // this is a fragment
    const char *filename2 = "testdata/message/NS-message-for-msgsize";
    buffer = load_binary_file(filename2, &buffer_size);

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        isc_result_t res = dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);

        // main test
        unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
        unsigned count[DNS_SECTION_MAX] = {0};
        msgsize = calc_message_size(msg, &nr_sig_rr, &nr_dnskey_rr, &total_size_sig_rr, &total_size_dnskey_rr, &savings, count, DNS_SECTION_MAX);
        assert_int_equal(msgsize, 888); // real-size
        //assert_int_equal(msgsize, 921);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }

    // this is a fragment
    const char *filename3 = "testdata/message/NS-message-for-msgsize2";
    buffer = load_binary_file(filename3, &buffer_size);

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        isc_result_t res = dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);

        // main test
        unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
        unsigned count[DNS_SECTION_MAX] = {0};
        msgsize = calc_message_size(msg, &nr_sig_rr, &nr_dnskey_rr, &total_size_sig_rr, &total_size_dnskey_rr, &savings, count, DNS_SECTION_MAX);
        assert_int_equal(msgsize, 1218); // real size
        //assert_int_equal(msgsize, 1329); 
        assert_int_equal(savings, 50);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
}

ISC_RUN_TEST_IMPL(estimate_message_size_test) {
    // Frag 1 should contain 2 sigs and 2 keys (falcon-512)
    const char *filename = "testdata/message/frag1_response1-falcon512";
    const char *src_address = "1.2.3.4";
    buffer = load_binary_file(filename, &buffer_size);

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        //isc_buffer_printf(&buf, "aa");
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);

        // main test
        unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
        msgsize = estimate_message_size(msg, &total_size_sig_rr, &total_size_dnskey_rr, &savings);
        assert_int_equal(msgsize, 3244);
        assert_int_equal(total_size_sig_rr, 1332);
        assert_int_equal(total_size_dnskey_rr, 1794);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }

    // This fragment should contain 7 resource records: 3 signatures (falcon-512), 2 A, 1 OPT, and 1 NS
    // Should lead to 2 fragments and a size of 2206 bytes
    const char *filename2 = "testdata/message/falcon_estimate_2_frags";
    buffer = load_binary_file(filename2, &buffer_size);

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        //isc_buffer_printf(&buf, "aa");
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);

        // main test
        unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
        msgsize = estimate_message_size(msg, &total_size_sig_rr, &total_size_dnskey_rr, &savings);
        assert_int_equal(total_size_sig_rr, 1998);
        assert_int_equal(total_size_dnskey_rr, 0);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
}

ISC_LOOP_TEST_IMPL(fragment_and_reassemble) {

    /*
    Name: response1-falcon512 
    Original PCAP file: /home/dev/qbf_src/data/resolver/mode 1/FALCON512.pcap
    Source: root NS (172.20.0.3)
    Destination: resolver (172.20.0.2)
    Size: 3244 bytes
    Nr. of fragments: 3
    */    
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    const char *filename = "testdata/message/response1-falcon512";
    const char *src_address = "172.20.0.3";
    buffer = load_binary_file(filename, &buffer_size);

    // outputs
    isc_result_t res;
    isc_buffer_t *out = NULL;
    fragment_cache_entry_t *out_ce;

    // initialize fcache
    fcache_t *fcache = NULL;
    fcache_init(&fcache, loopmgr, 10, 20);

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        //isc_buffer_printf(&buf, "aa");
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        // create key
        unsigned char key[64];
        unsigned keysize = sizeof(key) / sizeof(key[0]);
        fcache_create_key(msg->id, src_address, key, &keysize);

        // main test
        assert_int_equal(fcache_count(fcache), 0);
        res = fragment(mctx, fcache, msg, src_address, max_udp_size);
        assert_int_equal(fcache_count(fcache), 1); // one cache entry

        out_ce = NULL;
        res = fcache_get(fcache, key, keysize, &out_ce);
        assert_true(res == ISC_R_SUCCESS);
        assert_true(out_ce != NULL);
        // test number of fragments
        assert_int_equal(out_ce->nr_fragments, 3);
        // test fragment bitmap
        assert_true(out_ce->bitmap == ((1 << 0) | (1 << 1) | (1 << 2)));
        // raw byte comparison
        for(unsigned i = 1; i <= out_ce->nr_fragments; i++) {
            char frag1_filename[128];
            snprintf(frag1_filename, 128, "testdata/message/frag%u_response1-falcon512", i);
            unsigned char *frag1_buffer = NULL;
            size_t frag1_buffer_size;
            frag1_buffer = load_binary_file(frag1_filename, &frag1_buffer_size);
            if(frag1_buffer != NULL) {
                res = fcache_get_fragment(fcache, key, keysize, i-1, &out);
                assert_true(res == ISC_R_SUCCESS);
                //assert_int_equal(out->used, frag1_buffer_size);
                //for (unsigned j = 0; j < out->used; j++) {
                //    assert_true(((char *)(frag1_buffer))[j] == ((char *)(out->base))[j]);
                // }
                isc_mem_put(mctx, frag1_buffer, frag1_buffer_size);
            }
        }
        dns_message_t *out_msg = NULL;
        reassemble_fragments(mctx, fcache, key, keysize, &out_msg);
        assert_true(out_msg != NULL);
        assert_true(out_msg->buffer != NULL);
        assert_int_equal(out_msg->buffer->used, buffer_size);
        // start at three, TC is not set in testcase...
        for (unsigned i = 3; i < buffer_size; i++) {
            assert_true(((char *)(buffer))[i] == ((char *)(out_msg->buffer->base))[i]);
        }

        // clean up
        dns_message_detach(&msg);
        dns_message_detach(&out_msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }

    
    const char *filename2 = "testdata/message/falcon512-full-message";
    buffer = load_binary_file(filename2, &buffer_size);

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        //isc_buffer_printf(&buf, "aa");
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        // create key
        unsigned char key[64];
        unsigned keysize = sizeof(key) / sizeof(key[0]);
        fcache_create_key(msg->id, src_address, key, &keysize);

        // main test
        assert_int_equal(fcache_count(fcache), 0);
        res = fragment(mctx, fcache, msg, src_address, max_udp_size);
        assert_int_equal(fcache_count(fcache), 1); // one cache entry

        out_ce = NULL;
        res = fcache_get(fcache, key, keysize, &out_ce);
        assert_true(res == ISC_R_SUCCESS);
        assert_true(out_ce != NULL);
        // test number of fragments
        assert_int_equal(out_ce->nr_fragments, 3);
        // test fragment bitmap
        assert_true(out_ce->bitmap == ((1 << 0) | (1 << 1) | (1 << 2)));
        // raw byte comparison
        for(unsigned i = 1; i <= out_ce->nr_fragments; i++) {
            char frag1_filename[128];
            snprintf(frag1_filename, 128, "testdata/message/frag%u-falcon512-full-message", i);
            unsigned char *frag1_buffer = NULL;
            size_t frag1_buffer_size;
            frag1_buffer = load_binary_file(frag1_filename, &frag1_buffer_size);
            if(frag1_buffer != NULL) {
                res = fcache_get_fragment(fcache, key, keysize, i-1, &out);
                assert_true(res == ISC_R_SUCCESS);
                //assert_int_equal(out->used, frag1_buffer_size);
                isc_mem_put(mctx, frag1_buffer, frag1_buffer_size);
            }
        }
        dns_message_t *out_msg = NULL;
        reassemble_fragments(mctx, fcache, key, keysize, &out_msg);
        assert_true(out_msg != NULL);
        assert_true(out_msg->buffer != NULL);
        assert_int_equal(out_msg->buffer->used, buffer_size);
        // start at three, TC is not set in testcase...
        for (unsigned i = 3; i < buffer_size; i++) {
            assert_true(((char *)(buffer))[i] == ((char *)(out_msg->buffer->base))[i]);
        }

        // clean up
        dns_message_detach(&msg);
        dns_message_detach(&out_msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }

    // interesting case, because P256_FALCON uses four fragments but only three are used for RRSIG
    const char *filename3 = "testdata/message/P256_FALCON512";
    buffer = load_binary_file(filename3, &buffer_size);

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        // create key
        unsigned char key[64];
        unsigned keysize = sizeof(key) / sizeof(key[0]);
        fcache_create_key(msg->id, src_address, key, &keysize);

        // main test
        assert_int_equal(fcache_count(fcache), 0);
        res = fragment(mctx, fcache, msg, src_address, max_udp_size);
        assert_int_equal(fcache_count(fcache), 1); // one cache entry

        out_ce = NULL;
        res = fcache_get(fcache, key, keysize, &out_ce);
        assert_true(res == ISC_R_SUCCESS);
        assert_true(out_ce != NULL);
        // test number of fragments
        assert_int_equal(out_ce->nr_fragments, 4);
        // test fragment bitmap
        assert_true(out_ce->bitmap == ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3)));
        
        // raw byte comparison
        for(unsigned i = 1; i <= out_ce->nr_fragments; i++) {
            char frag1_filename[128];
            snprintf(frag1_filename, 128, "testdata/message/frag%u-P256_FALCON512", i);
            unsigned char *frag1_buffer = NULL;
            size_t frag1_buffer_size;
            frag1_buffer = load_binary_file(frag1_filename, &frag1_buffer_size);
            if(frag1_buffer != NULL) {
                res = fcache_get_fragment(fcache, key, keysize, i-1, &out);
                assert_true(res == ISC_R_SUCCESS);
                //assert_int_equal(out->used, frag1_buffer_size);
                isc_mem_put(mctx, frag1_buffer, frag1_buffer_size);
            }
        }
        dns_message_t *out_msg = NULL;
        reassemble_fragments(mctx, fcache, key, keysize, &out_msg);
        assert_true(out_msg != NULL);
        assert_true(out_msg->buffer != NULL);
        assert_int_equal(out_msg->buffer->used, buffer_size);
        // start at three, TC is not set in testcase...
        for (unsigned i = 3; i < buffer_size; i++) {
            assert_true(((char *)(buffer))[i] == ((char *)(out_msg->buffer->base))[i]);
        }

        // clean up
        dns_message_detach(&msg);
        dns_message_detach(&out_msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }

    // test for DILITHIUM2
    // we add an additional FORMERR response, which should not give any problem
    const char *filename4 = "testdata/message/response1-dilithium";
    buffer = load_binary_file(filename4, &buffer_size);

    if(buffer != NULL && false) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        // create key
        unsigned char key[64];
        unsigned keysize = sizeof(key) / sizeof(key[0]);
        fcache_create_key(msg->id, src_address, key, &keysize);

        // main test
        assert_int_equal(fcache_count(fcache), 0);
        res = fragment(mctx, fcache, msg, src_address, max_udp_size);
        assert_int_equal(fcache_count(fcache), 1); // one cache entry

        out_ce = NULL;
        res = fcache_get(fcache, key, keysize, &out_ce);
        assert_true(res == ISC_R_SUCCESS);
        assert_true(out_ce != NULL);
        // test number of fragments
        assert_int_equal(out_ce->nr_fragments, 7);
        // test fragment bitmap
        assert_true(out_ce->bitmap == ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6)));
        

        dns_message_t *out_msg = NULL;
        isc_result_t result = reassemble_fragments(mctx, fcache, key, keysize, &out_msg);
        assert_true(result == ISC_R_SUCCESS);
        assert_true(out_msg != NULL);
        assert_true(out_msg->buffer != NULL);
        assert_int_equal(out_msg->buffer->used, buffer_size);
        // start at three, TC is not set in testcase...
        for (unsigned i = 3; i < buffer_size; i++) {
            assert_true(((char *)(buffer))[i] == ((char *)(out_msg->buffer->base))[i]);
        }

        // increase nr_fragments and check if we get a ISC_R_INPROGRESS result
        res = fragment(mctx, fcache, msg, src_address, max_udp_size);
        dns_message_t *out_msg2 = NULL;
        out_ce->nr_fragments++;
        result = reassemble_fragments(mctx, fcache, key, keysize, &out_msg2);
        assert_true(result == ISC_R_INPROGRESS);
        out_ce->nr_fragments--;
        // try to fragment again, should not work because key still exists
        res = fragment(mctx, fcache, msg, src_address, max_udp_size);
        assert_true(res == ISC_R_EXISTS);

        // FORMERR response for ID 0x676f (WRONG ID)
        unsigned char formerr_bytes[] = {
            0x67, 0x6f, 0x86, 0x21, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x06, 0x3f, 0x32, 0x3f,
            0x6e, 0x73, 0x31, 0x07, 0x65, 0x78, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x05, 0x6c, 0x6f, 0x63, 0x61,
            0x6c, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x29, 0x04, 0xd0, 0x00, 0x00, 0x80, 0x00, 0x00,
            0x00
        };
        dns_message_t *formerr_frag = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &formerr_frag);
        isc_buffer_t formerr_buf;
        isc_buffer_init(&formerr_buf, formerr_bytes, sizeof(formerr_bytes));
        isc_buffer_putmem(&formerr_buf, formerr_bytes, sizeof(formerr_bytes));
        //isc_buffer_add(&formerr_buf, sizeof(formerr_bytes));
        formerr_frag->buffer = &formerr_buf;
        formerr_frag->fragment_nr = 7;
        // create a new entry
        unsigned newkeysize = 96;
        unsigned char newkey[newkeysize];
        strcpy((char *)newkey, "thisisakey!");
        fcache_add(fcache, newkey, newkeysize, out_ce->nr_fragments + 1);
        // copy fragments
        for (unsigned i = 0; i < out_ce->nr_fragments; i++) {
            dns_message_t *tmp = NULL;
            dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &tmp);
            isc_buffer_t *out_buf = NULL;
            fcache_get_fragment(fcache, key, keysize, i, &out_buf);
            dns_message_parse(tmp, out_buf, DNS_MESSAGEPARSE_PRESERVEORDER);
            tmp->fragment_nr = i;
            fcache_add_fragment(fcache, newkey, newkeysize, tmp);
            dns_message_detach(&tmp);
        }

        out_ce = NULL;
        res = fcache_get(fcache, newkey, newkeysize, &out_ce);
        assert_true(res == ISC_R_SUCCESS);
        result = fcache_add_fragment(fcache, newkey, newkeysize, formerr_frag);
        assert_true(result == ISC_R_SUCCESS);


        // ID should mismatch
        dns_message_t *out_msg3 = NULL;
        //result = reassemble_fragments(mctx, fcache, newkey, newkeysize, &out_msg3);
        //assert_true(result == ISC_R_FAILURE);
        //assert_true(out_msg3 == NULL);

        // set correct ID
        *(unsigned char *)(out_ce->fragments[formerr_frag->fragment_nr]->base) = 0xd5;
        *(unsigned char *)(out_ce->fragments[formerr_frag->fragment_nr]->base + 1) = 0x09;
        dns_message_t *out_msg4 = NULL;
        result = reassemble_fragments(mctx, fcache, newkey, newkeysize, &out_msg4);
        assert_true(result == ISC_R_SUCCESS);
        assert_true(out_msg4 != NULL);
        assert_true(out_msg4->buffer != NULL);
        assert_int_equal(out_msg4->buffer->used, buffer_size);
        // start at three, TC is not set in testcase...
        for (unsigned i = 3; i < buffer_size; i++) {
            assert_true(((char *)(buffer))[i] == ((char *)(out_msg4->buffer->base))[i]);
        }

        // clean up
        dns_message_detach(&msg);
        dns_message_detach(&out_msg);
        if (out_msg2 != NULL) {
            dns_message_detach(&out_msg2);
        }
        dns_message_detach(&formerr_frag);
        if (out_msg3 != NULL) {
            dns_message_detach(&out_msg3);
        }
        if (out_msg4 != NULL) {
            dns_message_detach(&out_msg4);
        }
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename4);
    }

    // this was causing some issues with the fragment
    // first fragments get underestimated: 1265 bytes instead of close to 1280 (including UDP header)
    // second fragment exceeds 1232 bytes... 
    const char *filename5 = "testdata/message/P256_FALCON512-test.example.local2";
    buffer = load_binary_file(filename5, &buffer_size);

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        // create key
        unsigned char key[64];
        unsigned keysize = sizeof(key) / sizeof(key[0]);
        fcache_create_key(msg->id, src_address, key, &keysize);
        fcache_purge(fcache);

        // main test
        assert_int_equal(fcache_count(fcache), 0);
        res = fragment(mctx, fcache, msg, src_address, max_udp_size);
        assert_true(res == ISC_R_SUCCESS);
        assert_int_equal(fcache_count(fcache), 1); // one cache entry

        out_ce = NULL;
        res = fcache_get(fcache, key, keysize, &out_ce);

        assert_true(res == ISC_R_SUCCESS);
        assert_true(out_ce != NULL);
        // test number of fragments
        assert_int_equal(out_ce->nr_fragments, 3);
        // test fragment bitmap
        assert_true(out_ce->bitmap == ((1 << 0) | (1 << 1) | (1 << 2)));

        dns_message_t *out_msg = NULL;
        reassemble_fragments(mctx, fcache, key, keysize, &out_msg);
        assert_true(out_msg != NULL);
        assert_true(out_msg->buffer != NULL);
        assert_int_equal(out_msg->buffer->used, buffer_size);
        // start at three, TC is not set in testcase...
        for (unsigned i = 3; i < buffer_size; i++) {
            assert_true(((char *)(buffer))[i] == ((char *)(out_msg->buffer->base))[i]);
        }

        // clean up
        dns_message_detach(&msg);
        dns_message_detach(&out_msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }

    fcache_deinit(&fcache);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_RUN_TEST_IMPL(test_query_creation) {

    /*
    Name: response1-falcon512 
    Original PCAP file: /home/dev/qbf_src/data/resolver/mode 1/FALCON512.pcap
    Source: root NS (172.20.0.3)
    Destination: resolver (172.20.0.2)
    Size: 3244 bytes
    Nr. of fragments: 3
    */
    const char *filename = "testdata/message/response1-falcon512";
    const char *src_address = "172.20.0.3";
    buffer = load_binary_file(filename, &buffer_size);

    // outputs
    bool res;
    if(buffer != NULL) {

        isc_buffer_t input_buffer;
        isc_region_t region;
        region.base = buffer;
        region.length = buffer_size;
		isc_buffer_init(&input_buffer, region.base, region.length);
		isc_buffer_add(&input_buffer, region.length);

        // main test
        dns_message_t *query = NULL; 
        isc_buffer_t *query_buffer = NULL;
        isc_region_t *query_region = NULL;
        res = get_fragment_query_raw(mctx, &input_buffer, 3, &query, &query_buffer); 

        size_t exp_buffer_size;
        const char *exp_filename = "testdata/message/response1-falcon512-query3";
        unsigned char *expected_buffer = load_binary_file(exp_filename, &exp_buffer_size);
        assert_true(expected_buffer != NULL);
        if (expected_buffer != NULL) {
            assert_int_equal(exp_buffer_size, query_buffer->used);
            for (unsigned i = 0; i < exp_buffer_size; i++) {
                assert_true(((char *)(expected_buffer))[i] == ((char *)(query_buffer->base))[i]);
            }
            isc_mem_put(mctx, expected_buffer, exp_buffer_size);
        }

        // clean up
        if (query != NULL) {
            dns_message_detach(&query);
        }
        if (query_buffer != NULL) {
            isc_buffer_free(&query_buffer);
        }
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
}




ISC_TEST_LIST_START
ISC_TEST_ENTRY(get_nr_fragments_test)
ISC_TEST_ENTRY(calc_message_size_test)
ISC_TEST_ENTRY(estimate_message_size_test)
ISC_TEST_ENTRY_CUSTOM(fragment_and_reassemble, setup_test, teardown_test)
ISC_TEST_ENTRY(test_query_creation)
ISC_TEST_ENTRY(calculate_start_end_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
