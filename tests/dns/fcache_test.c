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
#include <sys/param.h>
#include <unistd.h>
#include <time.h>
#include <isc/loop.h>

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

#include <dns/fcache.h>
#include <dns/message.h>

#include <tests/dns.h>

static int
setup_test(void **state) {
	setup_loopmgr(state);

	return (0);
}

static int
teardown_test(void **state) {
	teardown_loopmgr(state);
	return (0);
}

// tests basic insertion and deletion
ISC_LOOP_TEST_IMPL(basic) {
    
    // initialize
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    fcache_init(mainloop);
    
    // set up a dns message with random buffer
    dns_message_t *frag = NULL;
    isc_buffer_t *buffer = NULL;

    unsigned buflen = 10;
    isc_buffer_allocate(mctx, &buffer, buflen);
    frag = isc_mem_get(mctx, sizeof(dns_message_t));
    assert_int_equal(buffer->length, buflen);
    frag->fragment_nr = 1;
    frag->buffer = buffer;
    unsigned nr_fragments = 5;
    unsigned keysize = 96;
    unsigned char key[keysize];
    unsigned char key_non_exist[keysize];
    strcpy((char *)key, "thisisakey!");
    strcpy((char *)key_non_exist, "thisisalsoakey!");
    
    // outputs
    bool res;
    isc_buffer_t *out = NULL;
    fragment_cache_entry_t *out_ce = NULL;

    assert_int_equal(fcache_count(), 0);
    // add new message to cache
    res = fcache_add(key, keysize, frag, nr_fragments);
    assert_true(res);
    assert_int_equal(fcache_count(), 1);
    // get existing fragment
    res = fcache_get_fragment(key, keysize, frag->fragment_nr, out);
    assert_true(res);
    // get non-existing fragment
    res = fcache_get_fragment(key, keysize, 2, out);
    assert_false(res);
    // remove non-existing fragment
    res = fcache_remove_fragment(key, keysize, 2);
    assert_false(res);
    assert_int_equal(fcache_count(), 1);
    // remove fragment with non-existing key
    res = fcache_remove_fragment(key_non_exist, keysize, frag->fragment_nr);
    assert_false(res);
    assert_int_equal(fcache_count(), 1);
    // remove fragment
    res = fcache_remove_fragment(key, keysize, frag->fragment_nr);
    assert_true(res);
    assert_int_equal(fcache_count(), 1); // entry still exists
    // remove non-existing entry
    res = fcache_remove(key_non_exist, keysize);
    assert_false(res);
    // remove entry
    res = fcache_remove(key, keysize);
    assert_true(res);
    assert_int_equal(fcache_count(), 0);

    // deallocate memory
    isc_buffer_free(&buffer);
    isc_mem_put(mctx, frag, sizeof(dns_message_t));
    fcache_deinit();
	isc_loopmgr_shutdown(loopmgr);
}

// tests the fragmentation cache with real dns messages
ISC_LOOP_TEST_IMPL(real_dns_messages) {

}

ISC_LOOP_TEST_IMPL(expire) {
    // initialize
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    fcache_init(mainloop);

    // add something to cache
    // set up a dns message with random buffer
    dns_message_t *frag = NULL;
    isc_buffer_t *buffer = NULL;
    unsigned buflen = 10;
    isc_buffer_allocate(mctx, &buffer, buflen);
    frag = isc_mem_get(mctx, sizeof(dns_message_t));
    assert_int_equal(buffer->length, buflen);
    frag->fragment_nr = 1;
    frag->buffer = buffer;
    unsigned nr_fragments = 5;
    unsigned keysize = 96;
    unsigned char key[keysize];
    strcpy((char *)key, "thisisakey!");

    // outputs
    bool res;
    isc_buffer_t *out = NULL;
    fragment_cache_entry_t *out_ce = NULL;
    fragment_cache_entry_t *out_ce2 = NULL;

    // add new message to cache
    res = fcache_add(key, keysize, frag, nr_fragments);
    assert_true(res);
    res = fcache_get(key, keysize, &out_ce);
    assert_true(res);
    // sleep(15);
    time_t start = time(NULL);
    while (difftime(time(NULL), start) < 15) {
    }
    res = fcache_get(key, keysize, &out_ce2);
    assert_true(res);

    // wait 1 sec

    // add something new to cache

    // wait 1 sec

    // add something new

    // wait 13 (hardcoded)

    // check if cache is empty

    //fcache_deinit();
	//isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(purge) {
    // initialize
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    fcache_init(mainloop);

    //fcache_deinit();
	//isc_loopmgr_shutdown(loopmgr);
}



ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(basic, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(expire, setup_test, teardown_test)
//ISC_TEST_ENTRY_CUSTOM(purge, setup_test, teardown_test)
// ISC_TEST_ENTRY_CUSTOM(duplicate fragment, setup_test, teardown_test)
//ISC_TEST_ENTRY(basic)
//ISC_TEST_ENTRY_CUSTOM(expire, setup_loopmgr, teardown_loopmgr)
//ISC_TEST_ENTRY_CUSTOM(purge, setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
