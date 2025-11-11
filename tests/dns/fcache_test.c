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
        //assert_int_equal(msg->saved.length, out_ce->fragments[0]->used);

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



ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(basic, setup_test, teardown_test)
ISC_TEST_ENTRY_CUSTOM(real_dns_messages, setup_test, teardown_test)
//ISC_TEST_ENTRY_CUSTOM(expire, setup_test, teardown_test)
//ISC_TEST_ENTRY_CUSTOM(purge, setup_test, teardown_test)
// ISC_TEST_ENTRY_CUSTOM(duplicate fragment, setup_test, teardown_test)
//ISC_TEST_ENTRY(basic)
//ISC_TEST_ENTRY_CUSTOM(expire, setup_loopmgr, teardown_loopmgr)
//ISC_TEST_ENTRY_CUSTOM(purge, setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
