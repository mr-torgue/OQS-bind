#include <stdio.h>
#include <isc/mem.h>
#include <isc/util.h>
#include <isc/atomic.h>
#include <isc/loop.h>
#include <isc/types.h>
#include <isc/timer.h>
#include <dns/fcache.h>
#include "include/dns/fcache.h"

// schedules a time event after interval seconds
static void fcache_schedule_timer(isc_time_t *interval) {
    fprintf(stderr, "Setting timer at %d seconds...\n", isc_time_seconds(interval));
    isc_timer_start(expiry_timer, isc_timertype_ticker, interval);
}

// callback when a timer goes off
static void fcache_timer_cb(void *arg) {
    fprintf(stderr, "Executing callback...\n");
    REQUIRE(2==3);
    /*
    isc_time_t now = isc_time_now();
    fragment_cache_entry_t *entry, *next;

    for (entry = ISC_LIST_HEAD(expiry_list); entry != NULL; entry = next) {
        next = ISC_LIST_NEXT(entry, link);
        // remove if expired
        if (isc_time_compare(&(entry->expiry), &now) <= 0) {
            fcache_remove(entry->key, entry->keysize);
        } else {
            break;  // remaining entries are not yet expired
        }
    }

    // reschedule the timer for the next expiry (if any)
    if (ISC_LIST_HEAD(expiry_list) != NULL) {
        fprintf(stderr, "Callback is rescheduling timer...\n");
        isc_time_t delta;
        isc_time_t new_time = ISC_LIST_HEAD(expiry_list)->expiry;
        REQUIRE(isc_time_compare(&now, &new_time) >= 0);
        isc_time_subtract(&now, &new_time, &delta);
        // check if delta is small
        if (isc_time_compare(&delta, &loop_timeout) == -1) {
            delta = loop_timeout;
        }
        fcache_schedule_timer(&delta);
    }
    */
}

void fcache_init(isc_loop_t *loop) {
    fprintf(stderr, "Initializing fragment cache...\n");
    REQUIRE(loop != NULL);
    REQUIRE(frag_mctx == NULL);
    REQUIRE(fragment_cache == NULL);
    REQUIRE(expiry_timer == NULL);
    isc_mem_create(&frag_mctx);
    //frag_loop = isc_loop_current(frag_loopmgr);
	//isc_mem_attach(ntatable->mctx, &nta->mctx);
	//isc_loop_attach(isc_loop_main(frag_loopmgr_p), &frag_loop);
	//isc_loop_attach(isc_loop_current(frag_loopmgr), &frag_loop);
    isc_time_set(&fragment_ttl, 10, 0); // hardcoded
    isc_time_set(&loop_timeout, 0, 0);  // hardcoded
    isc_ht_init(&fragment_cache, frag_mctx, 16, 0); // use size 2^16, case sensitive 
    ISC_LIST_INIT(expiry_list);
    isc_timer_create(loop, fcache_timer_cb, NULL, &expiry_timer);
    fcache_schedule_timer(&loop_timeout);

}

void fcache_deinit(void) {    
    fprintf(stderr, "Deinitializing fragment cache...\n");
    isc_timer_destroy(&expiry_timer);
    // empty expiry list
    //while (!ISC_LIST_EMPTY(expiry_list)) {
    //    ISC_LIST_UNLINK(expiry_list, ISC_LIST_HEAD(expiry_list), link);
    //}
    fcache_purge();
    isc_ht_destroy(&fragment_cache); // entries get freed here
    isc_mem_destroy(&frag_mctx);
}


static bool fcache__add(isc_ht_t *ht, fragmentlist_t expiry_list_p, unsigned char *key, unsigned keysize, dns_message_t *frag, unsigned nr_fragments) {
    fprintf(stderr, "Adding fragment cache entry with key %s...\n", (char *)key);
    // lookup in cache
    fragment_cache_entry_t *entry = NULL;
    isc_result_t result = isc_ht_find(ht, key, keysize, (void **)&entry);

    // first fragment: create fragment in cache
    if (result == ISC_R_NOTFOUND) {    
        // duplicate key (we need for the timer cb)
        unsigned char *key_copy = isc_mem_get(frag_mctx, keysize);
        memcpy(key_copy, key, keysize);

        // create a new cache entry
        isc_time_t now = isc_time_now();
        entry = isc_mem_get(frag_mctx, sizeof(*entry));
        entry->nr_fragments = nr_fragments;
        entry->bitmap = 0;
        entry->fragments = isc_mem_get(frag_mctx, nr_fragments * sizeof(isc_buffer_t *));
        entry->key = key_copy;
        entry->keysize = keysize;

        isc_time_add(&now, &fragment_ttl, &(entry->expiry)); // set entry expiry time 
        isc_ht_add(ht, key, keysize, entry);             // add to hashtable
        ISC_LIST_APPEND(expiry_list_p, entry, link);          // add to linked list

        // schedule a timer for this entry if it's the earliest
        //if (ISC_LIST_HEAD(expiry_list_p) == entry) {
        //    fcache_schedule_timer(&fragment_ttl);
        //}
    }

    // check if already exists
    if (entry->bitmap & (1 << frag->fragment_nr)) {
        isc_buffer_free(&(entry->fragments[frag->fragment_nr]));
    }
    
    // copy into a new buffer
    isc_buffer_t *frag_buf = NULL;
    isc_buffer_dup(frag_mctx, &frag_buf, frag->buffer);

    // Store the fragment
    entry->fragments[frag->fragment_nr] = frag_buf;
    entry->bitmap |= (1 << frag->fragment_nr);
    return true;
}

// convencience function, uses the global fragment cache and expiry list
bool fcache_add(unsigned char *key, unsigned keysize, dns_message_t *frag, unsigned nr_fragments) {
    return fcache__add(fragment_cache, expiry_list, key, keysize, frag, nr_fragments);
}

static void fcache_free_entry(fragment_cache_entry_t *entry) {
    //ISC_LIST_UNLINK(expiry_list, entry, link);
    for (unsigned i = 0; i < entry->nr_fragments; i++) {
        if(entry->bitmap & (1 << i)) {
            isc_buffer_free(&(entry->fragments[i]));
        }
    }
    isc_mem_put(frag_mctx, entry->fragments, entry->nr_fragments * sizeof(isc_buffer_t *));
    isc_mem_put(frag_mctx, entry->key, entry->keysize);
    isc_mem_put(frag_mctx, entry, sizeof(fragment_cache_entry_t));    
}

static bool fcache__remove(isc_ht_t *ht, fragmentlist_t expiry_list_p, unsigned char *key, unsigned keysize) {
    fprintf(stderr, "Removing entry with key %s...\n", (char *)key);
    fragment_cache_entry_t *entry = NULL;
    if (isc_ht_find(ht, key, keysize, (void **)&entry) == ISC_R_SUCCESS) {
        // remove from hash table and free memory
        if(isc_ht_delete(fragment_cache, key, keysize) == ISC_R_SUCCESS) {
            ISC_LIST_UNLINK(expiry_list_p, entry, link);
            for (unsigned i = 0; i < entry->nr_fragments; i++) {
                isc_buffer_free(&(entry->fragments[i]));
            }
            isc_mem_put(frag_mctx, entry->fragments, entry->nr_fragments * sizeof(isc_buffer_t *));
            isc_mem_put(frag_mctx, entry->key, entry->keysize);
            isc_mem_put(frag_mctx, entry, sizeof(fragment_cache_entry_t));
            return true;
        }   
        fprintf(stderr, "Could not delete element with key: %s\n", key);
        return false;
    }
    fprintf(stderr, "could not find element with key: %s\n", key);
    return false;
}


bool fcache_remove(unsigned char *key, unsigned keysize) {
    return fcache__remove(fragment_cache, expiry_list, key, keysize);
}

static bool fcache__get(isc_ht_t *ht, fragmentlist_t expiry_list_p, unsigned char *key, unsigned keysize, fragment_cache_entry_t **out_cache_entry) {
    fprintf(stderr, "Getting fragment cache entry with key %s...\n", (char *)key);
    return (isc_ht_find(ht, key, keysize, (void **)out_cache_entry) == ISC_R_SUCCESS);
}

bool fcache_get(unsigned char *key, unsigned keysize, fragment_cache_entry_t **out_cache_entry) {
    return fcache__get(fragment_cache, expiry_list, key, keysize, out_cache_entry);
}

static bool fcache__get_fragment(isc_ht_t *ht, fragmentlist_t expiry_list_p, unsigned char *key, unsigned keysize, unsigned fragment_nr, isc_buffer_t **out_frag) {
    fprintf(stderr, "Getting fragment %u with key %s...\n", fragment_nr, (char *)key);
    fragment_cache_entry_t *entry = NULL;
    if (isc_ht_find(ht, key, keysize, (void **)&entry) == ISC_R_SUCCESS) {
        out_frag = entry->fragments[fragment_nr];
        return true;
    }
    return false; 
}

bool fcache_get_fragment(unsigned char *key, unsigned keysize, unsigned fragment_nr, isc_buffer_t **out_frag) {
    return fcache__get_fragment(fragment_cache, expiry_list, key, keysize, fragment_nr, out_frag);
}

bool fcache_purge(void) {
    fprintf(stderr, "Purging fragment cache...\n");
    isc_ht_iter_t *iterator = NULL;
    fragment_cache_entry_t *entry = NULL;
    isc_ht_iter_create(fragment_cache, &iterator);
    isc_result_t res = isc_ht_iter_first(iterator);
    while (res == ISC_R_SUCCESS) {
        isc_ht_iter_current(iterator, (void **)&entry);
        REQUIRE(entry != NULL);
        fcache_free_entry(entry);
        res = isc_ht_iter_delcurrent_next(iterator); // remove the current element
    }
    isc_ht_iter_destroy(&iterator); // remove iterator
    return true;
}

unsigned fcache_count(void) {
    // check with expiry_list?
    return isc_ht_count(fragment_cache);
}