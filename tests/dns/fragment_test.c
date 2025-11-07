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
#include <isc/sockaddr.h>
#include <isc/types.h>
#include <dns/types.h>

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

#include <dns/fragment.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/fixedname.h>

#include <tests/dns.h>

// global variables so the teardown function can deallocate
static dns_message_t *msg = NULL;
unsigned char *buffer = NULL;
size_t buffer_size;

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

static void compare_buffers(isc_buffer_t *a, isc_buffer_t *b) {
    printf("Comparing buffers...\n");
    printf("a->used: %d\nb->used: %d\n", a->used, b->used);
    assert_true(a->used == b->used);
    for (unsigned i = 0; i < a->used; i++) {
        assert_true(((char *)(a->base))[i] == ((char *)(b->base))[i]);
    }
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

// prints a DNS message properly
// copied from somewhere else
static void printmessage(dns_message_t *msg) {
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


ISC_RUN_TEST_IMPL(is_fragment_test) {
    dns_message_t *msg = NULL;
    dns_fixedname_t fname;
    dns_name_t *name = NULL;

    typedef struct {
        const char *qname;  
        bool is_fragment; 
        unsigned frag_nr;
        bool valid;
    } FragmentTestcase;

    FragmentTestcase testcases[] = {
        {"?1?test.com", true, 1, true},
        {"?12?.somethingsomething.com.com.com", true, 12, true},
        {"example.ca", false, 0, true},
        {"?some.xyz", false, 0, true},
        {"?12af?.example.com", false, 0, true}, // not a number between ??
        {"something.?12?example.com", false, 0, true}, // should start with fragment
        {"?1243?.dfhhdjjhhd.com", true, 1243, true},
        {"a?1243?.com", false, 0, true},
        {"?1243?..com", false, 0, false}, // invalid qname
    };

    name = dns_fixedname_initname(&fname);
    dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &msg);
    
    for (unsigned i = 0; i < sizeof(testcases) / sizeof(testcases[0]); i++) {
        fprintf(stderr, "testcase %d: %s\n", i, testcases[i].qname);
        char *qname = NULL;
        dns_name_fromstring(name, testcases[i].qname, NULL, 0, mctx);
        dns_message_addname(msg, name, DNS_SECTION_QUESTION);
        
        fprintf(stderr, "dns_message_firstname(msg, DNS_SECTION_QUESTION) == ISC_R_SUCCESS\n");
        bool res = is_fragment(mctx, msg);
        assert_true(dns_message_firstname(msg, DNS_SECTION_QUESTION) == ISC_R_SUCCESS); // qname should be there
        fprintf(stderr, "is_fragment(mctx, msg) == testcases[i].is_fragment...\nExpected: %d\nResult: %d\n", testcases[i].is_fragment, res);
        assert_true(res == testcases[i].is_fragment);                        // test if outcome is the same

        fprintf(stderr, "msg->is_fragment == testcases[i].is_fragment...\n");
        assert_true(msg->is_fragment == testcases[i].is_fragment); 
                                     // test if msg has been updated
        fprintf(stderr, "!msg->is_fragment || msg->fragment_nr == testcases[i].frag_nr...\n");
        fprintf(stderr, "%d || %lu == %d...\n", !msg->is_fragment, msg->fragment_nr, testcases[i].frag_nr);
        assert_true(!msg->is_fragment || msg->fragment_nr == testcases[i].frag_nr);              // test if fragment number has been parsed
        
        // test if msg has the correct qname
        dns_name_tostring(msg->cursors[DNS_SECTION_QUESTION], &qname, mctx);
        if (testcases[i].valid) {
            //fprintf(stderr, "strcmp(qname, testcases[i].qname) == 0...\n");
            assert_true(strcmp(qname, testcases[i].qname) == 0); 
        }

        // reset for next testcase
        dns_message_removename(msg, name, DNS_SECTION_QUESTION);
        dns_message_reset(msg, DNS_MESSAGE_INTENTRENDER);
        isc_mem_free(mctx, qname);
        dns_name_reset(name);

    }
    dns_message_detach(&msg);
}


//ISC_RUN_TEST_IMPL(calculate_start_end_test) {
    //calculate_start_end(frag_nr, nr_fragments, offsets[section_nr][counter], rr_sizes[section_nr][counter], can_send_first_fragment, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, &new_rdata_start, &new_rdata_length);
//}

ISC_RUN_TEST_IMPL(get_nr_fragments_test) {
    unsigned max_msg_size, total_msg_size, total_sig_pk_bytes, savings, can_send_first_msg, can_send, result;
    result = get_nr_fragments(1232, 1100, 900, 0, &can_send_first_msg, &can_send);
    assert_int_equal(result, 1);
    result = get_nr_fragments(1232, 1300, 900, 0, &can_send_first_msg, &can_send);
    assert_int_equal(result, 2);
}

ISC_RUN_TEST_IMPL(calc_message_size_test) {
    const char *filename = "testdata/message/response1-falcon512";
    const char *src_address = "1.2.3.4";
    buffer = load_binary_file(filename, &buffer_size);

    if(buffer != NULL) {
        printf("buffer_size: %lu\n", buffer_size);
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        printf("buf used: %d\n", buf.used);
        printf("buf used: %d\n", buf.length);
        //isc_buffer_printf(&buf, "aa");
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, 0);
        printf("msgid: %d\n", msg->id);
        //printbuffer(buffer, buffer_size);
        printmessage(msg);

        // main test
        unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
        msgsize = calc_message_size(msg, &nr_sig_rr, &nr_dnskey_rr, &total_size_sig_rr, &total_size_dnskey_rr, &savings);
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
}

ISC_RUN_TEST_IMPL(estimate_message_size_test) {
    const char *filename = "testdata/message/frag1_response1-falcon512";
    const char *src_address = "1.2.3.4";
    buffer = load_binary_file(filename, &buffer_size);

    if(buffer != NULL) {
        printf("buffer_size: %lu\n", buffer_size);
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        printf("buf used: %d\n", buf.used);
        printf("buf used: %d\n", buf.length);
        //isc_buffer_printf(&buf, "aa");
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, 0);
        printf("msgid: %d\n", msg->id);
        //printbuffer(buffer, buffer_size);
        printmessage(msg);

        // main test
        unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
        msgsize = estimate_message_size(msg, &total_size_sig_rr, &total_size_dnskey_rr, &savings);
        printf("msgsize: %u\n", msgsize);
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
    const char *filename = "testdata/message/response1-falcon512";
    const char *src_address = "172.20.0.3";
    buffer = load_binary_file(filename, &buffer_size);

    // outputs
    bool res;
    isc_buffer_t *out = NULL;
    fragment_cache_entry_t *out_ce;

    if(buffer != NULL) {
        fcache_init(mainloop);
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        printf("buf used: %d\n", buf.used);
        printf("buf used: %d\n", buf.length);
        //isc_buffer_printf(&buf, "aa");
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, 0);
        printf("msgid: %d\n", msg->id);
        //printbuffer(buffer, buffer_size);
        printmessage(msg);
        // create key
        unsigned char key[64];
        unsigned keysize = sizeof(key) / sizeof(key[0]);
        printf("here");
        fcache_create_key(msg->id, src_address, key, &keysize);
        printf("key: %s\n", key);

        // main test
        assert_int_equal(fcache_count(), 0);
        res = fragment(mctx, msg, src_address);
        printf("Number of cache entries: %u\n", fcache_count());
        assert_int_equal(fcache_count(), 1); // one cache entry

        out_ce = NULL;
        res = fcache_get(key, keysize, &out_ce);
        assert_true(res);
        printf("res: %u\n", res);
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
                res = fcache_get_fragment(key, keysize, i-1, &out);
                printf("res: %u\n", res);
                assert_true(res);
                printf("used: %u\nfragment size: %u\n", out->used, frag1_buffer_size);
                assert_int_equal(out->used, frag1_buffer_size);
                printbuffer(frag1_buffer, 128);
                printbuffer(out->base, 128);
                for (unsigned i = 0; i < out->used; i++) {
                    assert_true(((char *)(frag1_buffer))[i] == ((char *)(out->base))[i]);
                }
                isc_mem_put(mctx, frag1_buffer, frag1_buffer_size);
            }
        }
        dns_message_t *out_msg = NULL;
        reassemble_fragments(mctx, out_ce, &out_msg);
        printf("res: %u\n", res);
        printf("%u\n", out_msg == NULL);
        assert_true(out_msg != NULL);
        assert_true(out_msg->buffer != NULL);
        printf("msg size: %u\n", out_msg->buffer->length);
        printf("msg used: %u\n", out_msg->buffer->used);
        assert_int_equal(out_msg->buffer->used, buffer_size);
        printbuffer(buffer + 1840, 128);
        printbuffer(out_msg->buffer->base + 1840, 128);
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
    fcache_deinit();
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
ISC_TEST_ENTRY(is_fragment_test)
ISC_TEST_ENTRY(get_nr_fragments_test)
ISC_TEST_ENTRY(calc_message_size_test)
ISC_TEST_ENTRY(estimate_message_size_test)
//ISC_TEST_ENTRY(calculate_start_end_test)
ISC_TEST_ENTRY_CUSTOM(fragment_and_reassemble, setup_test, teardown_test)
ISC_TEST_ENTRY(test_query_creation)
ISC_TEST_LIST_END

ISC_TEST_MAIN
