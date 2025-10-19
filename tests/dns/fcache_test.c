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
    //setup_mctx(state);
	setup_loopmgr(state);

	return (0);
}

static int
teardown_test(void **state) {
	teardown_loopmgr(state);
    //teardown_mctx(state);

	return (0);
}

ISC_LOOP_TEST_IMPL(basic) {
    // initialize
    assert_true(loopmgr != NULL);
    //isc_loopmgr_run(loopmgr);
    fcache_init(mainloop);
    
    // set up a dns message with random buffer
    isc_mem_t *myctx = NULL;
    dns_message_t *frag = NULL;
    isc_buffer_t *buffer = NULL;
    unsigned buflen = 10;
    isc_mem_create(&myctx);
    isc_buffer_allocate(myctx, &buffer, buflen);
    frag = isc_mem_get(myctx, sizeof(dns_message_t));
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

    // add new message to cache
    res = fcache_add(key, keysize, frag, nr_fragments);
    assert_true(res);
    //res = fcache_get_fragment(key, keysize, frag->fragment_nr, &out);
    //assert_true(res);
    //res = fcache_get(key, keysize, &out_ce);
    //assert_true(res);
    //assert_true(out_ce != NULL);
    //assert_int_equal(out_ce->nr_fragments, nr_fragments);
    
    //assert_int_equal(out_ce->nr_fragments, nr_fragments);
    //assert_int_equal(out->length, buffer->length);
    //assert_int_equal(out->used, buffer->used);
    //for(unsigned i = 0; i < out->used; i++) {
    //    assert_true(((char *)(out->base))[i] == ((char *)(buffer->base))[i]);
    //}
    
    // check if message is added

    // add a fragment

    // remove something from cache


    // add multiple things to cache

    fcache_deinit();
	isc_loopmgr_shutdown(loopmgr);
}


static void
setup_test_run(void *data) {
}

ISC_LOOP_TEST_IMPL(expire) {
    // isc_loopmgr_run(loopmgr);
	//isc_loop_setup(mainloop, setup_test_run, NULL);
    fcache_init(mainloop);
    // add something to cache
    // set up a dns message with random buffer
    isc_mem_t *myctx = NULL;
    dns_message_t *frag = NULL;
    isc_buffer_t *buffer = NULL;
    unsigned buflen = 10;
    isc_mem_create(&myctx);
    isc_buffer_allocate(myctx, &buffer, buflen);
    frag = isc_mem_get(myctx, sizeof(dns_message_t));
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
    fprintf(stderr, "Hello from stderr!\n");
    //fprintf(stdout, "Hello from stdout!");
    assert_true(res);

    // wait 1 sec

    // add something new to cache

    // wait 1 sec

    // add something new

    // wait 13 (hardcoded)

    // check if cache is empty

    fcache_deinit();
	isc_loopmgr_shutdown(loopmgr);
}

ISC_RUN_TEST_IMPL(purge) {
    // add something to cache

    // check if added

    // flush

    // check if empty
}



ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(basic, setup_loopmgr, teardown_loopmgr)
// ISC_TEST_ENTRY_CUSTOM(duplicate fragment, setup_test, teardown_test)
//ISC_TEST_ENTRY(basic)
ISC_TEST_ENTRY_CUSTOM(expire, setup_loopmgr, teardown_loopmgr)
//ISC_TEST_ENTRY_CUSTOM(purge, setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
