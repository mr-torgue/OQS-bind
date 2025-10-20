#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <dns/message.h>
#include <isc/buffer.h>
#include <isc/ht.h>
#include <isc/job.h>
#include <isc/mem.h>
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
    uint16_t size;                  // size in bytes of complete message
    isc_buffer_t **fragments;        // raw buffers
    LINK(struct fragment_cache_entry) link;  // for the expiration list
} fragment_cache_entry_t;

typedef ISC_LIST(fragment_cache_entry_t) fragmentlist_t;

// global variables
static isc_mem_t *frag_mctx = NULL;            // for memory allocations
static isc_ht_t *fragment_cache = NULL;        // fragment hashtable
static fragmentlist_t expiry_list; // linked list to keep track of which fragment entries need to be removed
static isc_timer_t *expiry_timer = NULL;       // timer
static isc_time_t fragment_ttl;                // specifies ttl in the cache for a cache entry
static isc_time_t loop_timeout;                // loop executes at most once every loop_timeout times (prevents that loop triggers too many times)

// initializes the global variables
// initializes the timer (hardcoded intervals currently)
void fcache_init(isc_loop_t *frag_loopmgr_p);

// deinitializes the timer and cleans up
void fcache_deinit(void);

// add a fragment to cache
// creates a new cache entry if not exists
// if already exists, add to the fragments array
bool fcache_add(unsigned char *key, unsigned keysize, dns_message_t *frag, unsigned nr_fragments);

// removes a cache entry from cache
bool fcache_remove(unsigned char *key, unsigned keysize);

// returns a cache entry
// returns false if not in cache
bool fcache_get(unsigned char *key, unsigned keysize, fragment_cache_entry_t **out_cache_entry);

// returns the fragment in out_frag
// returns false if unsuccessful
bool fcache_get_fragment(unsigned char *key, unsigned keysize, unsigned fragment_nr, isc_buffer_t **out_frag);

// purges the cache (hashtable)
bool fcache_purge(void);

// return the number of elements in the cache
unsigned fcache_count(void);