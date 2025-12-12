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
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <isc/loop.h>
#include <isc/result.h>
#include <isc/time.h>
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

#include <dns/fcache.h>
#include <dns/message.h>

#include <tests/dns.h>

/*
static isc_timer_t *timer = NULL;
static isc_time_t endtime;
static isc_mutex_t lasttime_mx;
static isc_time_t lasttime;
static int seconds;
static int nanoseconds;
static atomic_int_fast32_t eventcnt;
static atomic_uint_fast32_t errcnt;
static int nevents;

typedef struct setup_test_arg {
	isc_timertype_t timertype;
	isc_interval_t *interval;
	isc_job_cb action;
} setup_test_arg_t;

// from isc/timer_test.c
static void
setup_test_run(void *data) {
	isc_timertype_t timertype = ((setup_test_arg_t *)data)->timertype;
	isc_interval_t *interval = ((setup_test_arg_t *)data)->interval;
	isc_job_cb action = ((setup_test_arg_t *)data)->action;

	isc_mutex_lock(&lasttime_mx);
	lasttime = isc_time_now();
	UNLOCK(&lasttime_mx);

	isc_timer_create(mainloop, action, (void *)timertype, &timer);
	isc_timer_start(timer, timertype, interval);
}

static void
setup_test(isc_timertype_t timertype, isc_interval_t *interval,
	   isc_job_cb action) {
	setup_test_arg_t arg = { .timertype = timertype,
				 .interval = interval,
				 .action = action };

	isc_time_settoepoch(&endtime);
	atomic_init(&eventcnt, 0);

	isc_mutex_init(&lasttime_mx);

	atomic_store(&errcnt, ISC_R_SUCCESS);

	isc_loop_setup(mainloop, setup_test_run, &arg);
	isc_loopmgr_run(loopmgr);

	assert_int_equal(atomic_load(&errcnt), ISC_R_SUCCESS);

	isc_mutex_destroy(&lasttime_mx);
}*/

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


// tests the init and deinit functions
ISC_LOOP_TEST_IMPL(test_fcache_init) {

    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    // test case 1: normal case
    fcache_t *fcache = NULL;
    fcache_init(&fcache, loopmgr, 10, 20);
    assert_true(fcache->mctx != NULL);
    assert_true(fcache->ht != NULL);
    assert_true(fcache->expiry_list.head == NULL);
    assert_true(fcache->expiry_list.tail == NULL);
    assert_true(fcache->expiry_timer != NULL);
    assert_int_equal(fcache->ttl.seconds, 10);
    assert_int_equal(fcache->loop_timeout.seconds, 20);
    fcache_deinit(&fcache);
    
    // test case 2: different values
    fcache = NULL;
    fcache_init(&fcache, loopmgr, 1, 1);
    assert_true(fcache->mctx != NULL);
    assert_true(fcache->ht != NULL);
    assert_true(fcache->expiry_list.head == NULL);
    assert_true(fcache->expiry_list.tail == NULL);
    assert_true(fcache->expiry_timer != NULL);
    assert_int_equal(fcache->ttl.seconds, 1);
    assert_int_equal(fcache->loop_timeout.seconds, 1);
    fcache_deinit(&fcache);
        
    // test case 3: different values
    fcache = NULL;
    fcache_init(&fcache, loopmgr, 12345, 98765);
    assert_true(fcache->mctx != NULL);
    assert_true(fcache->ht != NULL);
    assert_true(fcache->expiry_list.head == NULL);
    assert_true(fcache->expiry_list.tail == NULL);
    assert_true(fcache->expiry_timer != NULL);
    assert_int_equal(fcache->ttl.seconds, 12345);
    assert_int_equal(fcache->loop_timeout.seconds, 98765);
    fcache_deinit(&fcache);
    
	isc_loopmgr_shutdown(loopmgr);
}

// tests the add function
ISC_LOOP_TEST_IMPL(test_fcache_add) {

    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    fcache_t *fcache = NULL;
    fcache_init(&fcache, loopmgr, 10, 20);
    unsigned buflen = 16;
    unsigned nr_fragments = 5;
    unsigned frag_nr = 0;
    unsigned keysize = 96;
    unsigned char key[keysize];
    unsigned char key2[keysize];
    unsigned char key4[keysize];
    strcpy((char *)key, "thisisakey!");
    strcpy((char *)key2, "thisisanotherkey!");
    strcpy((char *)key2, "stillanotherkey!");
    fragment_cache_entry_t *out_ce;
    isc_result_t result;
    isc_time_t now = isc_time_now();

    // test case 1: normal case
    dns_message_t *frag1 = NULL;
    isc_buffer_t *buffer1 = NULL;
    isc_buffer_allocate(mctx, &buffer1, buflen);
    isc_buffer_putuint32(buffer1, 12345678);
    isc_buffer_putuint32(buffer1, 11111111); 
    frag1 = isc_mem_get(mctx, sizeof(dns_message_t));
    assert_int_equal(buffer1->length, buflen);
    frag1->fragment_nr = frag_nr;
    frag1->buffer = buffer1;
    result = fcache_add(fcache, key, keysize, frag1, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_get(fcache, key, keysize, &out_ce);
    assert_true(result == ISC_R_SUCCESS);
    assert_true(out_ce != NULL);
    assert_string_equal((char *)out_ce->key, (char *)key);
    assert_int_equal(out_ce->keysize, keysize);
    assert_int_equal(out_ce->nr_fragments, nr_fragments);
    assert_true(out_ce->bitmap == (1u << frag_nr));
    assert_true(out_ce->expiry.seconds > now.seconds - 10); // assumption that it takes less than 10 seconds

    // test case 2: new case with first frag set to 2
    out_ce = NULL;
    dns_message_t *frag2 = NULL;
    isc_buffer_t *buffer2 = NULL;
    frag_nr = 2;
    isc_buffer_allocate(mctx, &buffer2, buflen);
    isc_buffer_putuint32(buffer2, 53633633);
    isc_buffer_putuint32(buffer2, 11111221); 
    isc_buffer_putuint32(buffer2, 11111221); 
    frag2 = isc_mem_get(mctx, sizeof(dns_message_t));
    assert_int_equal(buffer2->length, buflen);
    frag2->fragment_nr = frag_nr;
    frag2->buffer = buffer2;
    result = fcache_add(fcache, key2, keysize, frag2, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);
    result = fcache_get(fcache, key2, keysize, &out_ce);
    assert_true(result == ISC_R_SUCCESS);
    assert_true(out_ce != NULL);
    assert_string_equal((char *)out_ce->key, (char *)key2);
    assert_int_equal(out_ce->keysize, keysize);
    assert_int_equal(out_ce->nr_fragments, nr_fragments);
    assert_true(out_ce->bitmap == (1u << frag_nr));
    assert_true(out_ce->expiry.seconds > now.seconds - 10); // assumption that it takes less than 10 seconds

    // test case 3: already exists
    result = fcache_add(fcache, key2, keysize, frag2, nr_fragments);
    assert_true(result == ISC_R_EXISTS);
    assert_true(out_ce->bitmap == (1u << frag_nr)); // just to check

    // test case 4: fragment number out of range
    out_ce = NULL;
    dns_message_t *frag4 = NULL;
    isc_buffer_t *buffer4 = NULL;
    frag_nr = 5;
    isc_buffer_allocate(mctx, &buffer4, buflen);
    isc_buffer_putuint32(buffer4, 53633633);
    isc_buffer_putuint32(buffer4, 11111221); 
    isc_buffer_putuint32(buffer4, 11111221); 
    frag4 = isc_mem_get(mctx, sizeof(dns_message_t));
    assert_int_equal(buffer4->length, buflen);
    frag4->fragment_nr = frag_nr;
    frag4->buffer = buffer4;
    result = fcache_add(fcache, key4, keysize, frag4, nr_fragments);
    assert_true(result == ISC_R_RANGE);
    result = fcache_get(fcache, key4, keysize, &out_ce);
    assert_true(result == ISC_R_SUCCESS);
    assert_true(out_ce != NULL);
    assert_string_equal((char *)out_ce->key, (char *)key4);
    assert_int_equal(out_ce->keysize, keysize);
    assert_int_equal(out_ce->nr_fragments, nr_fragments);
    assert_true(out_ce->expiry.seconds > now.seconds - 10); // assumption that it takes less than 10 seconds


    // free everything
    isc_buffer_free(&buffer1);
    isc_mem_put(mctx, frag1, sizeof(dns_message_t));
    isc_buffer_free(&buffer2);
    isc_mem_put(mctx, frag2, sizeof(dns_message_t));
    isc_buffer_free(&buffer4);
    isc_mem_put(mctx, frag4, sizeof(dns_message_t));
    fcache_deinit(&fcache);
	isc_loopmgr_shutdown(loopmgr);
}

typedef struct test_fcache {
    fcache_t *fcache;
    uint expected_count;

} test_fcache_t;

//static void timer_cleanup(void *data) {
//        isc_buffer_free(&buffer1);
//    isc_mem_put(mctx, frag1, sizeof(dns_message_t));
//    fcache_deinit(&fcache);
//	isc_loopmgr_shutdown(loopmgr);
//}

//static isc_timer_t *timer = NULL;
//static isc_time_t endtime;
//static isc_mutex_t lasttime_mx;
//static isc_time_t lasttime;
//static int seconds;
//static int nanoseconds;
//static atomic_int_fast32_t eventcnt;
//static atomic_uint_fast32_t errcnt;
//static int nevents;

// globals for timer testing
static isc_timer_t *timer_g = NULL;
static isc_timer_t *timer_2_g = NULL;
static fcache_t *fcache_g;
static unsigned expected_count_g;
static unsigned expected_count_2_g;
static unsigned nevents_g;

static void timer_cb(void *data) {
    nevents_g--;
    unsigned *expected_count = (unsigned *)data;
    printf("timer_cb, nevents_g: %u, expected_count: %u\n", nevents_g, *expected_count);
    assert_int_equal(fcache_count(fcache_g), *expected_count);
    // iterate
    // shutdown if 
    if (nevents_g == 0) {
		isc_timer_destroy(&timer_g);
		isc_timer_destroy(&timer_2_g);
        fcache_deinit(&fcache_g);
        isc_loopmgr_shutdown(loopmgr);
    }
}

ISC_LOOP_TEST_IMPL(test_fcache_expiry) {
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);

    nevents_g = 2;
    fcache_g = NULL;
    unsigned ttl = 3;
    unsigned timeout = 5;

    fcache_init(&fcache_g, loopmgr, ttl, timeout);
    // test case 1: 3 ttl and 5 second time-out
    unsigned buflen = 16;
    unsigned nr_fragments = 5;
    unsigned frag_nr = 0;
    unsigned keysize = 96;
    unsigned char key[keysize];
    strcpy((char *)key, "thisisakey!");
    fragment_cache_entry_t *out_ce;
    isc_result_t result;
    isc_time_t now = isc_time_now();

    // test case 1: normal case
    dns_message_t *frag1 = NULL;
    isc_buffer_t *buffer1 = NULL;
    isc_buffer_allocate(mctx, &buffer1, buflen);
    isc_buffer_putuint32(buffer1, 12345678);
    isc_buffer_putuint32(buffer1, 11111111); 
    frag1 = isc_mem_get(mctx, sizeof(dns_message_t));
    assert_int_equal(buffer1->length, buflen);
    frag1->fragment_nr = frag_nr;
    frag1->buffer = buffer1;
    result = fcache_add(fcache_g, key, keysize, frag1, nr_fragments);
    assert_true(result == ISC_R_SUCCESS);

    // test case 1
    expected_count_g = 1;
    isc_timer_create(isc_loop_main(loopmgr), timer_cb, &expected_count_g, &timer_g);
    isc_interval_t interval;
	isc_interval_set(&interval, 1, 0);
	isc_timer_start(timer_g, isc_timertype_once, &interval);

    // test case 2
    expected_count_2_g = 0;
    isc_timer_create(isc_loop_main(loopmgr), timer_cb, &expected_count_2_g, &timer_2_g);
    isc_interval_t interval2;
	isc_interval_set(&interval2, 6, 0);
	isc_timer_start(timer_2_g, isc_timertype_once, &interval2);


    // empty
    isc_buffer_free(&buffer1);
    isc_mem_put(mctx, frag1, sizeof(dns_message_t));
}

/*
// tests basic insertion and deletion
ISC_LOOP_TEST_IMPL(basic) {
    
    // initialize
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    fcache_init(mainloop);
    
    // set up a dns message with random buffer
    dns_message_t *frag = NULL;
    dns_message_t *frag2 = NULL;
    dns_message_t *frag4 = NULL;
    dns_message_t *frag5 = NULL;
    isc_buffer_t *buffer = NULL;
    isc_buffer_t *buffer2 = NULL;
    isc_buffer_t *buffer4 = NULL;
    isc_buffer_t *buffer5 = NULL;

    unsigned buflen = 10;
    // frag 1
    isc_buffer_allocate(mctx, &buffer, buflen);
    isc_buffer_putuint32(buffer, 12345678); // put some data
    frag = isc_mem_get(mctx, sizeof(dns_message_t));
    assert_int_equal(buffer->length, buflen);
    frag->fragment_nr = 1;
    frag->buffer = buffer;
    // frag 2
    isc_buffer_allocate(mctx, &buffer2, buflen);
    isc_buffer_putuint32(buffer2, 87654321); // put some data
    frag2 = isc_mem_get(mctx, sizeof(dns_message_t));
    frag2->fragment_nr = 2;
    frag2->buffer = buffer2;
    // frag 4
    isc_buffer_allocate(mctx, &buffer4, buflen);
    isc_buffer_putuint32(buffer4, 55555555); // put some data
    frag4 = isc_mem_get(mctx, sizeof(dns_message_t));
    frag4->fragment_nr = 4;
    frag4->buffer = buffer4;
    // frag 5 -> should not get added since nr_fragment = 5 (0, 1, 2, 3, 4)
    isc_buffer_allocate(mctx, &buffer5, buflen);
    isc_buffer_putuint32(buffer5, 88118811); // put some data
    frag5 = isc_mem_get(mctx, sizeof(dns_message_t));
    frag5->fragment_nr = 5;
    frag5->buffer = buffer5;

    unsigned nr_fragments = 5;
    unsigned keysize = 96;
    unsigned char key[keysize];
    unsigned char key_non_exist[keysize];
    strcpy((char *)key, "thisisakey!");
    strcpy((char *)key_non_exist, "thisisalsoakey!");
    
    // outputs
    bool res;
    isc_buffer_t *out = NULL;
    fragment_cache_entry_t *out_ce;

    assert_int_equal(fcache_count(), 0);
    // add new message to cache
    res = fcache_add(key, keysize, frag, nr_fragments);
    assert_true(res);
    assert_int_equal(fcache_count(), 1);
    // get existing fragment
    res = fcache_get_fragment(key, keysize, frag->fragment_nr, &out);
    assert_true(res);
    // get non-existing fragment
    res = fcache_get_fragment(key, keysize, 2, &out);
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

    // add new entry
    res = fcache_add(key, keysize, frag, nr_fragments);
    assert_true(res);
    assert_int_equal(fcache_count(), 1);
    // add same fragment, should overwrite
    res = fcache_add(key, keysize, frag, nr_fragments);
    assert_true(res);
    assert_int_equal(fcache_count(), 1);
    // add new fragment
    res = fcache_add(key, keysize, frag4, nr_fragments);
    assert_true(res);
    assert_int_equal(fcache_count(), 1);
    out_ce = NULL;
    res = fcache_get(key, keysize, &out_ce);
    assert_true(out_ce->bitmap == ((1 << frag->fragment_nr) | (1 << frag4->fragment_nr)));
    // try to add fragment 5
    res = fcache_add(key, keysize, frag5, nr_fragments);
    assert_false(res);
    assert_int_equal(fcache_count(), 1);
    out_ce = NULL;
    res = fcache_get(key, keysize, &out_ce);
    assert_true(out_ce->bitmap == ((1 << frag->fragment_nr) | (1 << frag4->fragment_nr)));
    // add new fragment
    res = fcache_add(key, keysize, frag2, nr_fragments);
    assert_true(res);
    assert_int_equal(fcache_count(), 1);
    out_ce = NULL;
    res = fcache_get(key, keysize, &out_ce);
    assert_true(out_ce->bitmap == ((1 << frag->fragment_nr) | (1 << frag4->fragment_nr) | (1 << frag2->fragment_nr)));

    // purge before loop
    fcache_purge();
    assert_int_equal(fcache_count(), 0);

    // add 100 entries, use the same fragment
    for(unsigned i = 0; i < 100; i++) {
        out_ce = NULL;
        unsigned char key2[keysize];
        snprintf((char *)key2, keysize, "key%d!", i);
        res = fcache_add(key2, keysize, frag, nr_fragments);
        assert_true(res);
        assert_int_equal(fcache_count(), i + 1);
        // test if fragment has been copied (e.g. does not use the same memory address)
        res = fcache_get(key2, keysize, &out_ce);
        assert_true(frag != out_ce);    // should have been copied
        assert_true(key2 != out_ce->key);
        assert_true(keysize == out_ce->keysize); // size should be the same
        assert_true(out_ce->bitmap == (1 << frag->fragment_nr));
        // get first fragment
        res = fcache_get_fragment(key2, keysize, frag->fragment_nr, &out);
        compare_buffers(frag->buffer, out);
    }

    // deallocate memory
    isc_buffer_free(&buffer);
    isc_buffer_free(&buffer2);
    isc_buffer_free(&buffer4);
    isc_buffer_free(&buffer5);
    isc_mem_put(mctx, frag, sizeof(dns_message_t));
    isc_mem_put(mctx, frag2, sizeof(dns_message_t));
    isc_mem_put(mctx, frag4, sizeof(dns_message_t));
    isc_mem_put(mctx, frag5, sizeof(dns_message_t));
    fcache_deinit();
	isc_loopmgr_shutdown(loopmgr);
}

// tests the fragmentation cache with real dns messages
ISC_LOOP_TEST_IMPL(real_dns_messages) {
    // initialize
    assert_true(loopmgr != NULL);
    assert_true(mctx != NULL);
    fcache_init(mainloop);
    
    // set up a dns message with random buffer
    dns_message_t *msg = NULL;
    isc_buffer_t *buffer = NULL;

    const char *filename = "testdata/message/response1-falcon512";
    const char *src_address = "1.2.3.4";
    unsigned buffer_size;
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

        unsigned nr_fragments = 5;
        unsigned keysize = 96;
        unsigned char key[keysize];
        unsigned char key_non_exist[keysize];
        strcpy((char *)key, "thisisakey!");
        strcpy((char *)key_non_exist, "thisisalsoakey!");
        
        // outputs
        bool res;
        isc_buffer_t *out = NULL;
        fragment_cache_entry_t *out_ce;

        assert_int_equal(fcache_count(), 0);
        // add new message to cache
        res = fcache_add(key, keysize, msg, nr_fragments);
        assert_true(res);
        assert_int_equal(fcache_count(), 1);
        out_ce = NULL;
        res = fcache_get(key, keysize, &out_ce);
        assert_true(res);
        assert_int_equal(out_ce->nr_fragments, nr_fragments);
        assert_int_equal(out_ce->bitmap, 1); // 000001
        printf("fragment size: %u, expected: %u\n", out_ce->fragments[0]->used, msg->saved.length);
        assert_int_equal(msg->saved.length, out_ce->fragments[0]->used);

        // clean up
        dns_message_detach(&msg);
        isc_mem_put(mctx, buffer, buffer_size);
    }
    else {
        fprintf(stderr, "Could not find file: %s\n", filename);
    }
    fcache_deinit();
	isc_loopmgr_shutdown(loopmgr);
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
*/


ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(test_fcache_init, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(test_fcache_add, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(test_fcache_expiry, setup_loopmgr, teardown_loopmgr)
//ISC_TEST_ENTRY_CUSTOM(basic, setup_test, teardown_test)
//ISC_TEST_ENTRY_CUSTOM(real_dns_messages, setup_test, teardown_test)
//ISC_TEST_ENTRY_CUSTOM(expire, setup_test, teardown_test)
//ISC_TEST_ENTRY_CUSTOM(purge, setup_test, teardown_test)
// ISC_TEST_ENTRY_CUSTOM(duplicate fragment, setup_test, teardown_test)
//ISC_TEST_ENTRY(basic)
//ISC_TEST_ENTRY_CUSTOM(expire, setup_loopmgr, teardown_loopmgr)
//ISC_TEST_ENTRY_CUSTOM(purge, setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
