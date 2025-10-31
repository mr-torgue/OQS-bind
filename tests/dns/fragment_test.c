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

static int
setup_test(void **state) {
	setup_loopmgr(state);

	return (0);
}

static int
teardown_test(void **state) {
	teardown_loopmgr(state);
    if(loopmgr != NULL) {
        fcache_deinit();
	    isc_loopmgr_shutdown(loopmgr);
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

    fprintf(stderr, "file_size: %d\n", file_size);
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
        int frag_nr;
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
    
    for (int i = 0; i < sizeof(testcases) / sizeof(testcases[0]); i++) {
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


ISC_RUN_TEST_IMPL(calculate_start_end_test) {
    //calculate_start_end(frag_nr, nr_fragments, offsets[section_nr][counter], rr_sizes[section_nr][counter], can_send_first_fragment, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, &new_rdata_start, &new_rdata_length);
    

}

ISC_RUN_TEST_IMPL(get_nr_fragments_test) {
    unsigned max_msg_size, total_msg_size, total_sig_pk_bytes, savings, can_send_first_msg, can_send, result;
    result = get_nr_fragments(1232, 1100, 900, 0, &can_send_first_msg, &can_send);
    assert_int_equal(result, 1);
    result = get_nr_fragments(1232, 1300, 900, 0, &can_send_first_msg, &can_send);
    assert_int_equal(result, 2);
    

ISC_RUN_TEST_IMPL(calc_message_size_test) {
    size_t buffer_size;
    const char *filename = "testdata/message/response1-falcon512";
    const char *src_address = "1.2.3.4";
    unsigned char *buffer = load_binary_file(filename, &buffer_size);

    if(buffer != NULL) {
        printf("buffer_size: %lu\n", buffer_size);
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        fprintf(stderr, "buf used: %d\n", buf.used);
        fprintf(stderr, "buf used: %d\n", buf.length);
        //isc_buffer_printf(&buf, "aa");
        dns_message_t *msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, 0);
        fprintf(stderr, "msgid: %d\n", msg->id);
        fprintf(stderr, "buffer: ");
        for(int i=0; i < buffer_size; i++) {
            fprintf(stderr, "%X ", buffer[i]);
        }
        fprintf(stderr, "\n");
        printmessage(msg);

        // main test
        unsigned msgsize, total_size_sig_rr, total_size_dnskey_rr, savings, nr_sig_rr, nr_dnskey_rr;
        unsigned **rr_sizes = NULL; // contains the size of each resource record
        msgsize = calc_message_size(mctx, msg, &rr_sizes, &nr_sig_rr, &nr_dnskey_rr, &total_size_sig_rr, &total_size_dnskey_rr, &savings);
        assert_int_equal(msgsize, 3244);
        assert_int_equal(nr_sig_rr, 2);
        assert_int_equal(nr_dnskey_rr, 2);
        assert_int_equal(total_size_sig_rr, 1332);
        assert_int_equal(total_size_dnskey_rr, 1794);

        // clean up
        if(rr_sizes != NULL) {
            for (unsigned section_nr = 1; section_nr < DNS_SECTION_MAX; section_nr++) {
                if(msg->counts[section_nr] > 0) {
                    isc_mem_put(mctx, rr_sizes[section_nr], msg->counts[section_nr] * sizeof(unsigned));
                }
            }
            isc_mem_put(mctx, rr_sizes, DNS_SECTION_MAX * sizeof(unsigned *));
        }
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
}



ISC_LOOP_TEST_IMPL(fragment_and_reassemble) {
    assert_true(loopmgr != NULL);
    size_t buffer_size;
    const char *filename = "testdata/message/response1-falcon512";
    const char *src_address = "1.2.3.4";
    unsigned char *buffer = load_binary_file(filename, &buffer_size);

    if(buffer != NULL) {
        fcache_init(mainloop);
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        fprintf(stderr, "buf used: %d\n", buf.used);
        fprintf(stderr, "buf used: %d\n", buf.length);
        //isc_buffer_printf(&buf, "aa");
        dns_message_t *msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, 0);
        fprintf(stderr, "msgid: %d\n", msg->id);
        fprintf(stderr, "buffer: ");
        for(int i=0; i < buffer_size; i++) {
            fprintf(stderr, "%X ", buffer[i]);
        }
        fprintf(stderr, "\n");
        printmessage(msg);

        // main test
        bool res = fragment(mctx, msg, src_address, strlen(src_address));

        // test number of fragments

        // test fragment numbers

        // raw byte comparison

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
	isc_loopmgr_shutdown(loopmgr);
}



ISC_TEST_LIST_START
ISC_TEST_ENTRY(is_fragment_test)
ISC_TEST_ENTRY(get_nr_fragments_test)
ISC_TEST_ENTRY(calc_message_size_test)
ISC_TEST_ENTRY_CUSTOM(fragment_and_reassemble, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
