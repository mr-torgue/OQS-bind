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
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/thread.h>
#include <isc/urcu.h>
#include <isc/util.h>
#include <isc/uv.h>

#include <dns/fcache.h>
#include <dns/message.h>

#include <tests/dns.h>



ISC_LOOP_TEST_IMPL(basic) {
    fcache_init(loopmgr);
    dns_message_t *frag = NULL;
    unsigned nr_fragments;
    unsigned keysize = 96;
    unsigned char key[keysize];
    // add new message to cache
    fcache_add(frag, nr_fragments, key, keysize);
	assert_int_equal(result, ISC_R_SUCCESS);
    
    // check if message is added

    // add a fragment

    // remove something from cache


    // add multiple things to cache


}

ISC_LOOP_TEST_IMPL(expire) {
    // add something to cache

    // wait 1 sec

    // add something new to cache

    // wait 1 sec

    // add something new

    // wait 13 (hardcoded)

    // check if cache is empty
}

ISC_LOOP_TEST_IMPL(flush) {
    // add something to cache

    // check if added

    // flush

    // check if empty
}



ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(basic, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(expire, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(purge, setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
