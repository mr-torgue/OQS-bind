#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <dns/message.h>
#include <isc/buffer.h>
#include <isc/ht.h>
#include <isc/job.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/time.h>
#include <isc/util.h>
#include <isc/loop.h>
#include <isc/timer.h>

/*
------------------------------------------------------------------------------------
FRAGMENT CACHING
------------------------------------------------------------------------------------
Author: Folmer Heikamp 
Year: 2025

We utulize the ISC cache (hash table) to store fragments
Hashtable key: transaction_id + src address + src port
We set a timer on the first expiring fragment
Prepend fragment cache functions with fcache for clarity

Notes:
1. To prevent collisions we can include hash(qname + qtype) in the key (TODO)
*/

typedef struct fragment_cache_entry {
    unsigned char *key;             // need to keep track of this for the linked list
    unsigned keysize;
    isc_time_t expiry;              // absolute time when this entry expires
    uint8_t nr_fragments;           // total fragments in response
    uint64_t bitmap;                // bitmask of received fragments
    isc_buffer_t **fragments;       // raw buffers
    LINK(struct fragment_cache_entry) link;  // for the expiration list
} fragment_cache_entry_t;

typedef ISC_LIST(fragment_cache_entry_t) fragmentlist_t;

typedef struct fcache {
	isc_mutex_t lock;               // to prevent multiple threads writing to cache
    isc_mem_t *mctx;                // for memory allocations
    isc_loopmgr_t *loopmgr;
    isc_ht_t *ht;                   // fragment hashtable
    fragmentlist_t expiry_list;     // linked list to keep track of which fragment entries need to be removed
    isc_timer_t *expiry_timer;      // timer ensuring cache remains clean
    isc_time_t ttl;                 // specifies ttl in the cache for a cache entry
    isc_time_t loop_timeout;        // loop executes at most once every loop_timeout times (prevents that loop triggers too many times)
    isc_time_t max_ttl_timeout;     // keeps track of MAX(ttl, loop_timeout)
} fcache_t;


// initializes the fache object
void fcache_init(fcache_t **fcache, isc_loopmgr_t *loopmgr, unsigned ttl, unsigned loop_timeout);

// deinitializes the timer and cleans up
void fcache_deinit(fcache_t **fcache);

// creates a new cache entry if not exists
// also adds the first fragment in the case of `fcache_add_with_fragment`
// returns:
//   ISC_R_EXISTS if already exists
//   ISC_R_SUCCESS if added
//   result of fcache_add_fragment_with_entry
isc_result_t fcache_add(fcache_t *fcache, unsigned char *key, unsigned keysize, unsigned nr_fragments);
isc_result_t fcache_add_with_fragment(fcache_t *fcache, unsigned char *key, unsigned keysize, dns_message_t *frag, unsigned nr_fragments);

// adds a new fragment to an existing entry
// if cache_entry is known, use `fcache_add_fragment_with_entry`
// does not create a new entry
// returns:
//   ISC_R_RANGE if frag_nr >= nr_fragments
//   ISC_R_NOTFOUND if no entry is found
//   ISC_R_SUCCESS if successfull
isc_result_t fcache_add_fragment_with_entry(fcache_t *fcache, fragment_cache_entry_t *entry, dns_message_t *frag);
isc_result_t fcache_add_fragment(fcache_t *fcache, unsigned char *key, unsigned keysize, dns_message_t *frag);

// removes a cache entry from cache
// returns:
//   ISC_R_SUCCESS
//   ISC_R_FAILURE if could not be deleted
//   ISC_R_NOTFOUND if not found 
isc_result_t fcache_remove(fcache_t *fcache, unsigned char *key, unsigned keysize);

// removes a fragment from a cache entry
// returns ISC_R_NOTFOUND if not found
isc_result_t fcache_remove_fragment(fcache_t *fcache, unsigned char *key, unsigned keysize, unsigned fragment_nr);

// returns a cache entry
// returns:
//   ISC_R_SUCCESS
//   ISC_R_NOTFOUND if not in cache
isc_result_t fcache_get(fcache_t *fcache, unsigned char *key, unsigned keysize, fragment_cache_entry_t **out_cache_entry);

// returns the fragment in out_frag
// `fcache_get_fragment_from_entry` skips the lookup part
// returns:
//   ISC_R_SUCCESS
//   ISC_R_NOTFOUND if not found
isc_result_t fcache_get_fragment_from_entry(fcache_t *fcache, fragment_cache_entry_t *entry, unsigned fragment_nr, isc_buffer_t **out_frag);
isc_result_t fcache_get_fragment(fcache_t *fcache, unsigned char *key, unsigned keysize, unsigned fragment_nr, isc_buffer_t **out_frag);

// purges the cache (hashtable)
isc_result_t fcache_purge(fcache_t *fcache);

// return the number of elements in the cache
unsigned fcache_count(fcache_t *fcache);

// frees a cache entry
void fcache_free_entry(fcache_t *fcache, fragment_cache_entry_t *entry);