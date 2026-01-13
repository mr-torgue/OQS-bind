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
#include <dns/enumclass.h>
#include <dns/fcache.h>
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

#include <dns/udp_fragmentation.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/fixedname.h>

#include <tests/dns.h>

// global variables so the teardown function can deallocate
static dns_message_t *msg = NULL;
unsigned char *buffer = NULL;
size_t buffer_size;
static unsigned max_udp_size = 1232;


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

// tests the is_fragment function (based on qname)
ISC_RUN_TEST_IMPL(test_is_fragment) {
    dns_fixedname_t fname;
    dns_name_t *name = NULL;

    typedef struct {
        const char *qname;  
        bool is_fragment; 
        unsigned frag_nr;
        bool valid;
    } FragmentTestcase;

    FragmentTestcase testcases[] = {
        {"?1?test.com", true, 0, true},
        {"?12?.somethingsomething.com.com.com", true, 11, true},
        {"example.ca", false, 0, true},
        {"?some.xyz", false, 0, true},
        {"?12af?.example.com", false, 0, true}, // not a number between ??
        {"something.?12?example.com", false, 0, true}, // should start with fragment
        {"?1243?.dfhhdjjhhd.com", true, 1242, true},
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
        
        bool res = is_fragment(mctx, msg);
        assert_true(dns_message_firstname(msg, DNS_SECTION_QUESTION) == ISC_R_SUCCESS); // qname should be there
        assert_true(res == testcases[i].is_fragment);                        // test if outcome is the same

        assert_true(msg->is_fragment == testcases[i].is_fragment); 
        // test if msg has been updated
        assert_true(!msg->is_fragment || msg->fragment_nr == testcases[i].frag_nr);              // test if fragment number has been parsed
        
        // test if msg has the correct qname
        dns_name_tostring(msg->cursors[DNS_SECTION_QUESTION], &qname, mctx);
        if (testcases[i].valid) {
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


ISC_RUN_TEST_IMPL(test_is_fragment_opt) {
    const char *filename = "testdata/udp_fragmentation/fragment_opt_test";
    const char *src_address = "1.2.3.4";
    buffer = load_binary_file(filename, &buffer_size);
    isc_result_t result;

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        msg->from_to_wire = 2;
        msg->state = DNS_SECTION_ANY;
        
        // test case 1: message with OPT but no option 22 : failure
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_NOTFOUND);

        // test case 2: add a valid OPT 22
        // 001001 (9) 001011 (11) 0000 (0)
        char opt_value_bytes[] = { 0x24, 0xB0};
        dns_rdataset_t *opt_2 = NULL;
        dns_ednsopt_t ednsopt;
        ednsopt.code = 22;
        ednsopt.length = 2;
        ednsopt.value = &opt_value_bytes;
        result = dns_message_buildopt(msg, &opt_2, 0, 1232, 0, &ednsopt, 1);
        dns_message_setopt(msg, opt_2);
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_SUCCESS);
        assert_int_equal(msg->fragment_nr, 9);
        assert_int_equal(msg->nr_fragments, 11);
        assert_int_equal(msg->fragment_flags, 0);
    


        // test case 3: message without OPT : failure
        dns_rdataset_t *temp_opt = msg->opt;
        msg->opt = NULL;
        result = is_fragment_opt(msg);
        assert_true(result == ISC_R_EMPTY);
        dns_message_setopt(msg, temp_opt);
        

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
    // test case 2: message with OPT but no option 22 : failure
    // test case 3: message with OPT but with option 21 : failure
    // test case 4: message with OPT and option 22 but data length is set to 0 : failure
    // test case 5: message with OPT and option 22 but data length is set to 3 : failure
    // test case 6: message with OPT and option 22 and data length is set to 2 : success
}

// tests if OPT records are correctly created
ISC_RUN_TEST_IMPL(test_create_fragment_opt) {
    const char *filename = "testdata/udp_fragmentation/fragment_opt_test";
    const char *src_address = "1.2.3.4";
    buffer = load_binary_file(filename, &buffer_size);
    isc_result_t result;

    if(buffer != NULL) {
        isc_buffer_t buf;
        isc_buffer_init(&buf, buffer, buffer_size);
        isc_buffer_add(&buf, buffer_size);
        msg = NULL;
        dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &msg);
        dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_PRESERVEORDER);
        msg->from_to_wire = 2;
        msg->state = DNS_SECTION_ANY;
        unsigned opt_size, nr_options;
        unsigned new_opt_size, new_nr_options;

        // test case 1: create a new OPTION in message without OPT record
        dns_rdataset_t *tmp_opt = msg->opt;
        msg->opt = NULL;
        parse_opt(msg, &opt_size, &nr_options);
        assert_int_equal(opt_size, 0);
        assert_int_equal(nr_options, 0);
        result = create_fragment_opt(msg, 1, 2, 0);
        parse_opt(msg, &new_opt_size, &new_nr_options);
        assert_true(result == ISC_R_SUCCESS);
        assert_true(msg->opt != NULL);
        assert_int_equal(new_opt_size, 17);
        assert_int_equal(new_nr_options, 1);
        dns_message_setopt(msg, tmp_opt);


        // test case 2: create a new OPTION in message with existing OPT record without data
        parse_opt(msg, &opt_size, &nr_options);
        assert_int_equal(opt_size, 11);
        assert_int_equal(nr_options, 0);
        result = create_fragment_opt(msg, 1, 2, 0);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }

    // test case 3: create a new OPTION in message that already has an OPTION 22
}

// tests if OPT records are properly created and subsequently detected by is_fragment
ISC_RUN_TEST_IMPL(test_create_and_is_fragment_opt) {
}



ISC_TEST_LIST_START
ISC_TEST_ENTRY(test_is_fragment)
ISC_TEST_ENTRY(test_is_fragment_opt)
ISC_TEST_ENTRY(test_create_fragment_opt)
ISC_TEST_ENTRY(test_create_and_is_fragment_opt)
ISC_TEST_LIST_END

ISC_TEST_MAIN
