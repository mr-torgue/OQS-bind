#include <stdio.h>
#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>
#include <isc/atomic.h>
#include <isc/loop.h>
#include <isc/types.h>
#include <isc/timer.h>
#include <dns/fcache.h>
#include "include/dns/fcache.h"


// callback when a timer goes off
static void fcache_timer_cb(void *arg) {
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Executing callback..."); 
    
    fcache_t *fcache = (fcache_t *)arg;
    isc_time_t now = isc_time_now();
    fragment_cache_entry_t *entry, *next;

    for (entry = ISC_LIST_HEAD(fcache->expiry_list); entry != NULL; entry = next) {
        next = ISC_LIST_NEXT(entry, link);
        // remove if expired
        if (isc_time_compare(&(entry->expiry), &now) <= 0) {
            isc_result_t result = fcache_remove(fcache, entry->key, entry->keysize);
        } else {
            break;  // remaining entries are not yet expired
        }
    }
}

void fcache_init(fcache_t **fcache, isc_loopmgr_t *loopmgr, unsigned ttl, unsigned loop_timeout) {
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Initializing fragment cache..."); 
    REQUIRE(fcache != NULL && *fcache == NULL);
    REQUIRE(ttl > 0);
    REQUIRE(loop_timeout > 0);
    
    // create memory context
    isc_mem_t *mctx = NULL;
    isc_mem_create(&mctx);

    // create and set fcache object
    *fcache = isc_mem_get(mctx, sizeof(fcache_t));
    (*fcache)->mctx =  mctx;
    isc_time_set( &(*fcache)->ttl, ttl, 0); 
    (*fcache)->ht = NULL;
    isc_time_set(&(*fcache)->loop_timeout, loop_timeout, 0); 
    isc_ht_init(&(*fcache)->ht, (*fcache)->mctx, 16, 0); // use size 2^16, case sensitive 
    ISC_LIST_INIT((*fcache)->expiry_list);
    (*fcache)->expiry_timer = NULL;
    (*fcache)->loopmgr = loopmgr;

    // start a timer that runs every x seconds
    isc_timer_create(isc_loop_current(loopmgr), fcache_timer_cb, *fcache, &(*fcache)->expiry_timer);
    isc_timer_start((*fcache)->expiry_timer, isc_timertype_ticker, &(*fcache)->loop_timeout); 

    // initialize mutex
	isc_mutex_init(&(*fcache)->lock);
}

void fcache_deinit(fcache_t **fcache) {    
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Deinitializing fragment cache..."); 
    if((*fcache)->expiry_timer != NULL) {
        isc_timer_destroy(&(*fcache)->expiry_timer);
    }
    fcache_purge(*fcache);
    isc_ht_destroy(&(*fcache)->ht); // entries get freed here
    isc_mutex_destroy(&(*fcache)->lock);
	isc_mem_putanddetach(&(*fcache)->mctx, *fcache, sizeof(**fcache));
}


isc_result_t fcache_add(fcache_t *fcache, unsigned char *key, unsigned keysize, unsigned nr_fragments) {
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Adding fragment cache entry with key %s (%u)...", (char *)key, keysize); 
    // lookup in cache
    fragment_cache_entry_t *entry = NULL;
    isc_result_t result = isc_ht_find(fcache->ht, key, keysize, (void **)&entry);

    // first fragment: create fragment in cache
    if (result == ISC_R_NOTFOUND) {    
        // duplicate key (we need for the timer cb)
        unsigned char *key_copy = isc_mem_get(fcache->mctx, keysize);
        memcpy(key_copy, key, keysize);

        // create a new cache entry
        isc_time_t now = isc_time_now();
        entry = isc_mem_get(fcache->mctx, sizeof(*entry));
        entry->nr_fragments = nr_fragments;
        entry->bitmap = 0;
        entry->fragments = isc_mem_get(fcache->mctx, nr_fragments * sizeof(isc_buffer_t *));
        entry->key = key_copy;
        entry->keysize = keysize;

        isc_time_add(&now, &fcache->ttl, &(entry->expiry)); // set entry expiry time 
        isc_ht_add(fcache->ht, key, keysize, entry);             // add to hashtable
        ISC_LIST_APPEND(fcache->expiry_list, entry, link);          // add to linked list
        return ISC_R_SUCCESS;
    }
    return ISC_R_EXISTS;
}

isc_result_t fcache_add_with_fragment(fcache_t *fcache, unsigned char *key, unsigned keysize, dns_message_t *frag, unsigned nr_fragments) {
    isc_result_t result = fcache_add(fcache, key, keysize, nr_fragments);
    if (result == ISC_R_SUCCESS) {
        return fcache_add_fragment(fcache, key, keysize, frag);
    }
    return result;
}

isc_result_t fcache_add_fragment_with_entry(fcache_t *fcache, fragment_cache_entry_t *entry, dns_message_t *frag) {
    REQUIRE(frag != NULL && (frag->buffer != NULL || frag->saved.base != NULL));
    if (frag->fragment_nr >= entry->nr_fragments) {
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
            "Can only add  where fragment_nr < nr_fragments: fragment_nr: %lu, nr_fragments: %u", frag->fragment_nr, entry->nr_fragments); 
        return ISC_R_RANGE;
    }
    // check if overwriting
    if (entry->bitmap & (1 << frag->fragment_nr)) {
        isc_buffer_free(&(entry->fragments[frag->fragment_nr]));
    }
    // copy into a new buffer
    isc_buffer_t *frag_buf = NULL;
    if (frag->buffer != NULL) {
        isc_buffer_dup(fcache->mctx, &frag_buf, frag->buffer);
    }
    else {
        isc_buffer_t tmp_buf;
        isc_buffer_init(&tmp_buf, frag->saved.base, frag->saved.length);
        isc_buffer_add(&tmp_buf, frag->saved.length);
        isc_buffer_dup(fcache->mctx, &frag_buf, &tmp_buf);
    }

    // Store the fragment
    entry->fragments[frag->fragment_nr] = frag_buf;
    entry->bitmap |= (1 << frag->fragment_nr);
    return ISC_R_SUCCESS;
}

isc_result_t fcache_add_fragment(fcache_t *fcache, unsigned char *key, unsigned keysize, dns_message_t *frag) {
    fragment_cache_entry_t *entry = NULL;
    isc_result_t result = isc_ht_find(fcache->ht, key, keysize, (void **)&entry); 
    if (result == ISC_R_SUCCESS) {   
        return fcache_add_fragment_with_entry(fcache, entry, frag);
    }
    return ISC_R_NOTFOUND;
}

isc_result_t fcache_remove(fcache_t *fcache, unsigned char *key, unsigned keysize) {
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Removing entry with key %s...", (char *)key); 
    fragment_cache_entry_t *entry = NULL;
    if (isc_ht_find(fcache->ht, key, keysize, (void **)&entry) == ISC_R_SUCCESS) {
        // remove from hash table and free memory
        if(isc_ht_delete(fcache->ht, key, keysize) == ISC_R_SUCCESS) {
            fcache_free_entry(fcache, entry);
            return ISC_R_SUCCESS;
        }   
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
            "Could not delete element with key: %s", key); 
        return ISC_R_FAILURE;
    }
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Could not find element with key: %s", key); 
    return ISC_R_NOTFOUND;
}


isc_result_t fcache_remove_fragment(fcache_t *fcache, unsigned char *key, unsigned keysize, unsigned fragment_nr) {
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Removing fragment %u with key %s...", fragment_nr, (char *)key); 
    fragment_cache_entry_t *entry = NULL;
    if (isc_ht_find(fcache->ht, key, keysize, (void **)&entry) == ISC_R_SUCCESS) {
        if(entry->bitmap & (1 << fragment_nr)) {
            isc_buffer_free(&(entry->fragments[fragment_nr]));
            entry->bitmap &= ~(1 << fragment_nr);
            return ISC_R_SUCCESS;
        }
        isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
            "Could not find fragment in cache entry: %s", key); 
        return ISC_R_NOTFOUND;
    }
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Could not find cache entry!"); 
    return ISC_R_NOTFOUND;
}

isc_result_t fcache_get(fcache_t *fcache, unsigned char *key, unsigned keysize, fragment_cache_entry_t **out_cache_entry) {
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Getting fragment cache entry with key %s (%u)...", (char *)key, keysize); 
    REQUIRE(*out_cache_entry == NULL);
    return isc_ht_find(fcache->ht, key, keysize, (void **)out_cache_entry);
}


isc_result_t fcache_get_fragment_from_entry(fcache_t *fcache, fragment_cache_entry_t *entry, unsigned fragment_nr, isc_buffer_t **out_frag) {
    if(entry->bitmap & (1 << fragment_nr)) {
        *out_frag = entry->fragments[fragment_nr];
        (*out_frag)->current = 0; // in case it is not set to the beginning
        return ISC_R_SUCCESS;
    }
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Could not find fragment %u!", fragment_nr);
    return ISC_R_NOTFOUND;
}


isc_result_t fcache_get_fragment(fcache_t *fcache, unsigned char *key, unsigned keysize, unsigned fragment_nr, isc_buffer_t **out_frag) {
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Getting fragment %u with key %s... (%u)", fragment_nr, (char *)key, keysize);
    fragment_cache_entry_t *entry = NULL;
    if (isc_ht_find(fcache->ht, key, keysize, (void **)&entry) == ISC_R_SUCCESS) {
        return fcache_get_fragment_from_entry(fcache, entry, fragment_nr, out_frag);
    }
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Could not find cache entry!");
    return ISC_R_NOTFOUND; 
}

isc_result_t fcache_purge(fcache_t *fcache) {
    isc_log_write(dns_lctx, DNS_LOGCATEGORY_FRAGMENTATION, DNS_LOGMODULE_FCACHE, ISC_LOG_DEBUG(10),
        "Purging fragment cache...");
    isc_ht_iter_t *iterator = NULL;
    isc_ht_iter_create(fcache->ht, &iterator);
    isc_result_t res = isc_ht_iter_first(iterator);
    while (res == ISC_R_SUCCESS) {
        fragment_cache_entry_t *entry = NULL;
        isc_ht_iter_current(iterator, (void **)&entry);
        REQUIRE(entry != NULL);
        fcache_free_entry(fcache, entry);
        res = isc_ht_iter_delcurrent_next(iterator); // remove the current element
    }
    isc_ht_iter_destroy(&iterator); // remove iterator
    return ISC_R_SUCCESS;
}

unsigned fcache_count(fcache_t *fcache) {
    return isc_ht_count(fcache->ht);
}

void fcache_free_entry(fcache_t *fcache, fragment_cache_entry_t *entry) {
    ISC_LIST_UNLINK(fcache->expiry_list, entry, link);
    for (unsigned i = 0; i < entry->nr_fragments; i++) {
        if(entry->bitmap & (1 << i) && entry->fragments[i] != NULL) {
            isc_buffer_free(&(entry->fragments[i]));
        }
    }
    isc_mem_put(fcache->mctx, entry->fragments, entry->nr_fragments * sizeof(isc_buffer_t *));
    isc_mem_put(fcache->mctx, entry->key, entry->keysize);
    isc_mem_put(fcache->mctx, entry, sizeof(fragment_cache_entry_t));    
}