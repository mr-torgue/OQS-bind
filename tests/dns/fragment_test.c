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

ISC_RUN_TEST_IMPL(is_fragment_t) {
    dns_message_t *msg = NULL;
    dns_fixedname_t fname;
    dns_name_t *name = NULL;
    isc_buffer_t buf;
    char *s = "?1?test.test.com";

    typedef struct {
        char *qname;  
        bool is_fragment; 
        int frag_nr;
    } FragmentTestcase;

    FragmentTestcase testcases[] = {
        {"?1?test.com", true, 1},
        {"?12?.somethingsomething.com.com.com", true, 12},
        {"example.ca", false, 0},
        {"?some.xyz", false, 0},
        {"?12af?.example.com", false, 0}, // not a number between ??
        {"something.?12?example.com", false, 0}, // should start with fragment
    };

    name = dns_fixedname_initname(&fname);
    //dns_name_fromstring(name, s, NULL, 0, mctx);       
    dns_message_addname(msg, name, DNS_SECTION_QUESTION);
    dns_message_create(mctx, DNS_MESSAGE_INTENTRENDER, &msg);
    //dns_message_addname(msg, name, DNS_SECTION_QUESTION);
    // test basic structure
    //assert_true(!msg->is_fragment);
    //assert_true(dns_message_firstname(msg, DNS_SECTION_QUESTION) == ISC_R_SUCCESS); // qname should be there
    //fprintf(stderr, "msg->cursors[DNS_SECTION_QUESTION]: %s\n", msg->cursors[DNS_SECTION_QUESTION]->ndata);
    
    char *qname = NULL;
    for (int i = 0; i < 1; i++) {
        dns_name_fromstring(name, testcases[i].qname, NULL, 0, mctx);
        assert_true(dns_message_firstname(msg, DNS_SECTION_QUESTION) == ISC_R_SUCCESS); // qname should be there
        assert_true(is_fragment(mctx, msg) == testcases[i].is_fragment);                        // test if outcome is the same
        assert_true(msg->is_fragment == testcases[i].is_fragment);                              // test if msg has been updated
        assert_true(msg->is_fragment && msg->fragment_nr == testcases[i].frag_nr);              // test if fragment number has been parsed
        // test if msg has the correct qname
        dns_name_tostring(msg->cursors[DNS_SECTION_QUESTION], &qname, mctx);
        assert_true(strcmp(qname, testcases[i].qname) == 0); 

        // reset for next testcase
        //dns_message_reset(msg, DNS_MESSAGE_INTENTRENDER);

    }


    dns_message_removename(msg, name, DNS_SECTION_QUESTION);
    isc_mem_free(mctx, qname);
    dns_message_detach(&msg);

}




ISC_TEST_LIST_START
ISC_TEST_ENTRY(is_fragment_t)
ISC_TEST_LIST_END

ISC_TEST_MAIN
