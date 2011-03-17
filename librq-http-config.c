//-----------------------------------------------------------------------------
// librq-http-config
//
//	This library is used by 

//-----------------------------------------------------------------------------


#include "rq-http-config.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if (RQ_HTTP_CONFIG_VERSION != 0x00011500)
	#error "Incorrect header version"
#endif

#if (LIBRQ_VERSION < 0x00010710)
	#error "librq v1.07.10 or higher is required"
#endif


#if ( _EVENT_NUMERIC_VERSION < 0x02000000 )

static struct event * evtimer_new(struct event_base *evbase, void (*fn)(int, short, void *), void *arg)
{
	struct event *ev;
	
	assert(evbase && fn);
	ev = calloc(1, sizeof(*ev));
	assert(ev);
	event_set(ev, -1, EV_TIMEOUT, fn, arg);
	event_base_set(evbase, ev);
	
	return(ev);
}

static void event_free(struct event *ev)
{
	assert(ev);
	event_del(ev);
	free(ev);
}
#endif


typedef struct {
	char *host;
	char *path;
	time_t expires;
	char *queue;
	char *propath;
	char *leftover;
	char *redirect;
} entry_t;


typedef struct {
	rq_hcfg_id_t id;
	void (*handler)(const char *queue, const char *path, const char *leftover, const char *redirect, void *arg);
	void *arg;
	rq_hcfg_t *cfg;
	rq_message_t *msg;
	char *host;
	char *path;
	entry_t *entry;
	struct event *timeout;

	// data returned
	expbuf_t *queue;
	expbuf_t *propath;
	expbuf_t *leftover;
	expbuf_t *redirect;
} waiting_t;


//-----------------------------------------------------------------------------
// Add an entry to the internal cache.
static void add_entry(waiting_t *waiting)
{
	entry_t *entry;
	struct timeval tv;
	time_t curtime;

	assert(waiting);

	entry = (entry_t *) malloc(sizeof(entry_t));
	assert(entry);

	// store the host and original path.
	assert(waiting->host);
	assert(waiting->path);
	entry->host = strdup(waiting->host);
	entry->path = strdup(waiting->path);

	// get the current time so that we can calculate the expiry time.
	gettimeofday(&tv, NULL);
	curtime=tv.tv_sec;
	assert(waiting->cfg);
	assert(waiting->cfg->expiry > 0);
	entry->expires = curtime + waiting->cfg->expiry;

	// we should definately have a queue... unless we have a redirect.
	if (waiting->queue) {
		assert(waiting->redirect == NULL);
		assert(BUF_LENGTH(waiting->queue) > 0);
		entry->queue = strdup(expbuf_string(waiting->queue));
	}
	else {
		entry->queue = NULL;
	}

	if (waiting->propath) { entry->propath = strdup(expbuf_string(waiting->propath)); }
	else { entry->propath = NULL; }

	if (waiting->leftover) { entry->leftover = strdup(expbuf_string(waiting->leftover)); }
	else { entry->leftover = NULL; }
	
	if (waiting->redirect) {
		assert(waiting->queue == NULL);
		assert(BUF_LENGTH(waiting->redirect) > 0);
		entry->redirect = strdup(expbuf_string(waiting->redirect));
	}
	else {
		entry->redirect = NULL;
	}

	// now add the entry to the cache list.
	assert(waiting->cfg);
	assert(waiting->cfg->cache);
	ll_push_head(waiting->cfg->cache, entry);

// 	fprintf(stderr, "http_config: Added entry to internal cache:  host=%s, path=%s, propath=%s, leftover=%s, queue=%s, redirect=%s\n",
// 		entry->host, entry->path, entry->propath, entry->leftover, entry->queue, entry->redirect);
}


static void entry_free(entry_t *entry)
{
	assert(entry);
	
	assert(entry->host);
	assert(entry->path);
	assert(entry->queue);
	free(entry->host);
	free(entry->path);
	free(entry->queue);
	if (entry->propath)  free(entry->propath);
	if (entry->leftover) free(entry->leftover);
	if (entry->redirect) free(entry->redirect);
}




//-----------------------------------------------------------------------------
// This callback function is to be fired when the CMD_CLEAR command is 
// received.  It should clear off any data received and stored in variables 
// and flags.  In otherwords, after this is executed, the node structure 
// should be in a predictable state.
static void cmdClear(waiting_t *ptr)
{
 	assert(ptr);
 	
 	if (ptr->queue)    { expbuf_clear(ptr->queue); }
	if (ptr->propath)  { expbuf_clear(ptr->propath); }
 	if (ptr->leftover) { expbuf_clear(ptr->leftover); }
 	if (ptr->redirect) { expbuf_clear(ptr->redirect); }
}


static void waiting_free(waiting_t *waiting)
{
	assert(waiting);
	
	assert(waiting->cfg);
	assert(waiting->cfg->rq);
	assert(waiting->cfg->rq->bufpool);
	
	if (waiting->redirect) {
		assert(waiting->queue == NULL);
		assert(waiting->propath == NULL);
		assert(waiting->leftover == NULL);
		expbuf_clear(waiting->redirect);
		expbuf_pool_return(waiting->cfg->rq->bufpool, waiting->redirect);
		waiting->redirect = NULL;
	}
	else {
		if (waiting->queue) {
			expbuf_clear(waiting->queue);
			expbuf_pool_return(waiting->cfg->rq->bufpool, waiting->queue);
			waiting->queue = NULL;
		}
		
		if (waiting->propath) {
			expbuf_clear(waiting->propath);
			expbuf_pool_return(waiting->cfg->rq->bufpool, waiting->propath);
			waiting->propath = NULL;
		}
		
		if (waiting->leftover) {
			expbuf_clear(waiting->leftover);
			expbuf_pool_return(waiting->cfg->rq->bufpool, waiting->leftover);
			waiting->leftover = NULL;
		}
	}
	
	if (waiting->host) free(waiting->host);
	if (waiting->path) free(waiting->path);
	
	// remove the 'waiting' entry from the waiting list... we've processed the reply.
	assert(waiting->cfg);
	assert(waiting->cfg->waiting);
	ll_remove(waiting->cfg->waiting, waiting);
	free(waiting);
}



//-----------------------------------------------------------------------------
// The host and path didn't match example, but a redirect could be determined.
// So we need to call the handler with the redirect path.
static void cmdRedirect(waiting_t *waiting, const risp_length_t length, const risp_data_t *data)
{
	assert(waiting);
	assert(length > 0);
	assert(data);

	assert(waiting->handler);
	assert(waiting->arg);
	assert(waiting->queue == NULL);
	assert(waiting->propath == NULL);
	assert(waiting->leftover == NULL);
	assert(waiting->redirect == NULL);

	assert(waiting->cfg);
	assert(waiting->cfg->rq);
	assert(waiting->cfg->rq->bufpool);
	waiting->redirect = expbuf_pool_new(waiting->cfg->rq->bufpool, length+1);
	expbuf_set(waiting->redirect, data, length);

	// add the result to the cache (if we have one)
	assert(waiting->cfg);
	if (waiting->cfg->cache) {
		add_entry(waiting);
	}
	
	waiting->handler(NULL, NULL, NULL, expbuf_string(waiting->redirect), waiting->arg);
}



static void cmdResult(waiting_t *waiting)
{
	assert(waiting);

	// check that we have the queue, path, and possibly leftover.
	assert(waiting->handler);
	assert(waiting->arg);
	assert(waiting->queue);
	assert(waiting->redirect == NULL);
	
	assert(waiting->cfg);
	if (waiting->cfg->cache) {
		add_entry(waiting);
	}
	
	waiting->handler(
		expbuf_string(waiting->queue),
		waiting->propath ? expbuf_string(waiting->propath) : NULL,
		waiting->leftover ? expbuf_string(waiting->leftover) : NULL,
		NULL,
		waiting->arg);
}


// Failed to find the appropriate queue, so we will return an error code to the client.
static void cmdFailed(waiting_t *waiting)
{
	assert(waiting);
	assert(waiting->handler);
	assert(waiting->arg);
	assert(waiting->queue == NULL);
	assert(waiting->redirect == NULL);
	
	assert(waiting->cfg);
	if (waiting->cfg->cache) {
		add_entry(waiting);
	}
	
	waiting->handler(
		waiting->queue ? expbuf_string(waiting->queue) : NULL,
		waiting->propath ? expbuf_string(waiting->propath) : NULL,
		waiting->leftover ? expbuf_string(waiting->leftover) : NULL,
		NULL,
		waiting->arg);

}




static void cmdQueue(waiting_t *waiting, const risp_length_t length, const risp_data_t *data)
{
	assert(waiting);
	assert(length > 0);
	assert(data);

	assert(waiting->handler);
	assert(waiting->arg);
	assert(waiting->redirect == NULL);

	if (waiting->queue == NULL) {
		assert(waiting->cfg);
		assert(waiting->cfg->rq);
		assert(waiting->cfg->rq->bufpool);
		waiting->queue = expbuf_pool_new(waiting->cfg->rq->bufpool, length+1);
	}

	expbuf_set(waiting->queue, data, length);
}


static void cmdPath(waiting_t *waiting, const risp_length_t length, const risp_data_t *data)
{
	assert(waiting);
	assert(length > 0);
	assert(data);

	assert(waiting->handler);
	assert(waiting->arg);

	if (waiting->propath == NULL) {
		assert(waiting->cfg);
		assert(waiting->cfg->rq);
		assert(waiting->cfg->rq->bufpool);
		waiting->propath = expbuf_pool_new(waiting->cfg->rq->bufpool, length+1);
	}

	expbuf_set(waiting->propath, data, length);
}

static void cmdLeftover(waiting_t *waiting, const risp_length_t length, const risp_data_t *data)
{
	assert(waiting);
	assert(length > 0);
	assert(data);

	assert(waiting->handler);
	assert(waiting->arg);

	if (waiting->leftover == NULL) {
		assert(waiting->cfg);
		assert(waiting->cfg->rq);
		assert(waiting->cfg->rq->bufpool);
		waiting->leftover = expbuf_pool_new(waiting->cfg->rq->bufpool, length+1);
	}

	expbuf_set(waiting->leftover, data, length);
}







//-----------------------------------------------------------------------------
void rq_hcfg_init(rq_hcfg_t *cfg, rq_t *rq, const char *queue, int expiry)
{
	assert(cfg && rq && queue);
	assert(expiry >= 0);
	
	cfg->rq = rq;
	cfg->queue = (char *) queue;
	
	cfg->expiry = expiry;
	if (expiry > 0) {
		cfg->cache = (list_t *) malloc(sizeof(list_t));
		ll_init(cfg->cache);
	}
	else {
		cfg->cache = NULL;
	}
	
	cfg->waiting = (list_t *) malloc(sizeof(list_t));
	ll_init(cfg->waiting);
	
	
	cfg->risp = risp_init(NULL);
	assert(cfg->risp);
	risp_add_command(cfg->risp, HCFG_CMD_CLEAR,    &cmdClear);
	risp_add_command(cfg->risp, HCFG_CMD_RESULT,   &cmdResult);
	risp_add_command(cfg->risp, HCFG_CMD_FAILED,   &cmdFailed);
	risp_add_command(cfg->risp, HCFG_CMD_REDIRECT, &cmdRedirect);
	risp_add_command(cfg->risp, HCFG_CMD_QUEUE,    &cmdQueue);
	risp_add_command(cfg->risp, HCFG_CMD_PATH,     &cmdPath);
	risp_add_command(cfg->risp, HCFG_CMD_LEFTOVER, &cmdLeftover);
}



//-----------------------------------------------------------------------------
void rq_hcfg_free(rq_hcfg_t *cfg)
{
	entry_t *entry;
	
	assert(cfg);

	cfg->rq = NULL;
	cfg->queue = NULL;

	// technically, there should not be anything 'waiting', as they should have all been cancelled or processed.
	assert(cfg->waiting);
	assert(ll_count(cfg->waiting) == 0);
	ll_free(cfg->waiting);
	free(cfg->waiting);
	cfg->waiting = NULL;

	if (cfg->cache) {
		while	((entry = ll_pop_head(cfg->cache))) {
			entry_free(entry);
			free(entry);
		}
		ll_free(cfg->cache);
		free(cfg->cache);
		cfg->cache = NULL;
	}

	assert(cfg->risp);
	cfg->risp = risp_shutdown(cfg->risp);
	assert(cfg->risp == NULL);

}

// return the next id we can use in the list.  We add new entries to the tail, and expect to fill requests from the head.
static rq_hcfg_id_t next_id(rq_hcfg_t *cfg)
{
	rq_hcfg_id_t id;
	waiting_t *waiting;

	assert(cfg);
	assert(cfg->waiting);

	waiting = ll_get_tail(cfg->waiting);
	if (waiting) { id = waiting->id + 1; }
	else         { id = 1; }

	assert(id > 0);
	return(id);
}



//-----------------------------------------------------------------------------
// Handle the response from the blacklist service.
static void config_result(rq_message_t *reply)
{
	waiting_t *waiting;
	int processed;

	assert(reply);
	waiting = reply->arg;
	assert(waiting);

	assert(waiting->msg == NULL);
	waiting->msg = reply;
	
	assert(reply->data);
	assert(waiting->cfg);
	assert(waiting->cfg->risp);
	processed = risp_process(waiting->cfg->risp, waiting, BUF_LENGTH(reply->data), BUF_DATA(reply->data));
	assert(processed == BUF_LENGTH(reply->data));

	waiting->msg = NULL;

	waiting_free(waiting);
}


//-----------------------------------------------------------------------------
// If the data we are looking for is found in the cache, then we need to set a 
// timeout to fire so that we can deliver the data as a callback.  This is 
// simulating what happens when we receive data from the config service.
static void timeout_handler(const int fd, const short which, void *arg)
{
	waiting_t *waiting = arg;
	
	assert(fd < 0);
	assert((which & EV_TIMEOUT) == EV_TIMEOUT);
	assert(waiting);
	
	assert(waiting->timeout);
	event_free(waiting->timeout);
	waiting->timeout = NULL;

	assert(waiting->msg == NULL);
	assert(waiting->entry);
	
	assert((waiting->entry->redirect && waiting->entry->queue == NULL && waiting->entry->path == NULL && waiting->entry->leftover == NULL) 
		|| (waiting->entry->redirect == NULL && waiting->entry->queue && waiting->entry->path));
	
	// Now execute the callback function that was specified for this action.
	assert(waiting->handler);
	waiting->handler(waiting->entry->queue, waiting->entry->path, waiting->entry->leftover, waiting->entry->redirect, waiting->arg);
	waiting_free(waiting);
}



//-----------------------------------------------------------------------------
// Lookup a host/path combo and call the handler when the information is
// available.  If the information was available in the cache, call the handler
// straight away, and then return a 0.  If we need to send a query to the
// config server, then return an id (that is greater than zero) which can be
// used to cancel the request (due to lost connection, or a blacklist deny,
// etc).
rq_hcfg_id_t rq_hcfg_lookup(
	rq_hcfg_t *cfg,
	const char *host,
	const char *path,
	void (*handler)(const char *queue, const char *path, const char *leftover, const char *redirect, void *arg),
	void *arg)
{
	entry_t *entry;
	entry_t *found;
	struct timeval tv;
	time_t curtime;
	rq_message_t *msg;
	waiting_t *waiting;
	rq_hcfg_id_t id;

	assert(cfg && host && path && handler && arg);

	// get the current time in seconds.
	gettimeofday(&tv, NULL);
	curtime=tv.tv_sec;

	// 'found' will contain the 'entry' if a valid one is found in the cache.
	found = NULL;
	
	// check the cache for the address.
	if (cfg->cache) {
		ll_start(cfg->cache);
		entry = ll_next(cfg->cache);
		while (entry) {
	
// 			fprintf(stderr, "http_config: Checking cache.  host: '%s'='%s', path: '%s'='%s'\n", host, entry->host, path, entry->path);
		
			if (strcasecmp(host, entry->host) == 0 && strcmp(path, entry->path) == 0) {

			
				// check to see if entry has expired.
				assert(entry->expires > 0);
				if (entry->expires <= curtime) {
					
// 					fprintf(stderr, "http_config: found.  entry expired.  entry=%d, curtime=%d\n", entry->expires, curtime);

					// cached entry has expired, so we need to remove it from the list.
					ll_remove(cfg->cache, entry);
					entry_free(entry);
					free(entry);
					entry = NULL;
					assert(found == NULL);
				}
				else {
					// entry is in the list, so we call the handler, and then we return 0.
					ll_move_head(cfg->cache, entry);
					ll_finish(cfg->cache);

// 					fprintf(stderr, "http_config: found entry in cache:  host=%s, path=%s, propath=%s, leftover=%s, queue=%s, redirect=%s\n",
// 						entry->host, entry->path, entry->propath, entry->leftover, entry->queue, entry->redirect);

					assert((entry->redirect && entry->leftover == NULL) || (entry->redirect == NULL));
					assert(found == NULL);
					found = entry;
					entry = NULL;
				}
				assert(entry == NULL);

			}
			else {
				entry = ll_next(cfg->cache);
			}
		}
		ll_finish(cfg->cache);
	}
	
	// get the next id.
	id = next_id(cfg);

	// create the structure that will hold the information we are waiting on, and add it to the tail of the list.
	waiting = (waiting_t *)  malloc(sizeof(waiting_t));
	assert(waiting);
	waiting->id = id;
	waiting->host = strdup(host);
	waiting->path = strdup(path);
	waiting->arg = arg;
	waiting->cfg = cfg;
	waiting->msg = NULL;
	waiting->handler = handler;
	waiting->queue = NULL;
	waiting->propath = NULL;
	waiting->leftover = NULL;
	waiting->redirect = NULL;
	
	assert(cfg->waiting);
	ll_push_tail(cfg->waiting, waiting);

	if (found) {
		waiting->entry = found;
		
		assert(cfg);
		assert(cfg->rq);
		assert(cfg->rq->evbase);
		
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		
		waiting->timeout = evtimer_new( cfg->rq->evbase, timeout_handler, waiting);
		evtimer_add(waiting->timeout, &tv);
		
	}
	else {
		// now create a message object so we can send the message
		assert(cfg->queue);
		assert(cfg->rq);
		msg = rq_msg_new(cfg->rq, NULL);
		assert(msg);
		assert(msg->data);

		// apply the queue that we are sending a request for.
		rq_msg_setqueue(msg, cfg->queue);

		
		// build the command payload.
		rq_msg_addcmd(msg, HCFG_CMD_CLEAR);
		rq_msg_addcmd_str(msg, HCFG_CMD_HOST, strlen(waiting->host), (char *)waiting->host);
		rq_msg_addcmd_str(msg, HCFG_CMD_PATH, strlen(waiting->path), (char *)waiting->path);
		rq_msg_addcmd(msg, HCFG_CMD_LOOKUP);

		// message has been prepared, so send it.
		// TODO: add fail handler.
		rq_send(msg, config_result, NULL, waiting);
		msg = NULL;
	}
	
	return(id);
}

void rq_hcfg_cancel(rq_hcfg_t *cfg, rq_hcfg_id_t id)
{
	assert(cfg);
	assert(id > 0);

	// look in the list of pending requests.

	// if id is in there cancel the request.
	assert(0);

	// remove entry from the list.
	assert(0);
	
}





