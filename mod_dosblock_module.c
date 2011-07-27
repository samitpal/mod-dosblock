/* Copyright 2011 Google Inc. All Rights Reserved.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *  http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"

#include "apr_global_mutex.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "apr_time.h"
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#define RULEURL "url"
#define RULEHEADER "header"
#define ARSIZE 300 /* No of seconds that we use to calculate the rate. Default is rate over 5 mins */
#define MAXRULE 20 /* Max number of dos rules that can be configured */

#ifdef AP_NEED_SET_MUTEX_PERMS
  #include "unixd.h"
#endif

/*--------------------------------------------------------------------------
 * mod_dosblock was developed to fill the need for dos protection at the http
 * layer. We hook at the post_read_request phase to catch problems early.  It
 * can be  configured to act on the url or the http header. It does not the
 * support combining two or more subrules. You can define a url based subrule
 * using the following syntax
 *
 * DosBlockUrl <name of the  url subrule> <pattern>
 *
 * example
 *
 * DosBlockUrl myurlrule /test
 *
 * Header based subrule can be defined as follows
 * DosBlockHeader <name of the header subrule> <headername>  <pattern>
 *
 * example
 *
 * DosBlockHeader myheaderrule User-Agent mozilla
 *
 * Then you use the following syntax to do the real blocking
 * DosBlockRule <dos rule name>:<name of the subrule> <threshold rate (hits per
 * sec)> <time to blocki ( in secs)>
 *
 * example
 *
 * DosBlockRule dosblock_header:myheaderrule 2 60
 *
 * A complete example
 *
 * DosBlockUrl myurlrule /test
 * DosBlockRule blocktest:myurlrule 50 120
 *
 * In case you want to enable debugging you can set
 *
 * DosBlockVerbose On
 *
 * Its off by default
 *
 * I plan to add support for combining subrules in a subsequent release
 *
 ---------------------------------------------------------------------------*/

apr_shm_t *dosblockipc_shm[MAXRULE]; /* Array of pointers to shared memory blocks */
char *shmfilename; /* Shared memory file name, used on some systems */
char *mutex_filename;
apr_global_mutex_t *dosblockipc_mutex[MAXRULE]; /* Array of mutex locks around shared memory segments */

/* Config related data structure */
typedef struct {
    apr_table_t *urlrules;
    apr_hash_t *headerrules;
    apr_table_t *ruletype;          /* Table to store the type of the subrule i.e(url or header) */
    apr_table_t *dosrulemap;        /* Mapping between the dos rule and the subrule */
    apr_hash_t *dosrules;           /* This hash map stores in its value object of type dosrulestruct */
    apr_hash_t *dosrule_shm_map;    /* Mapping between the dos rule and the shared mem segment */
    apr_table_t *dosrule_mutex_map; /* Mapping between the dos rule and the mutext */
    int verbosity;                  /* Used to log messages  based on what we have here */
}dosblock_cfg;

/* struct to hold info about header based subrule.
 * Note that we do not need any struct for url based subrule as a normal table is sufficient.
 */

typedef struct {
    char *headername;
    char *headerpattern;
}headerrulestruct;

/* Struct to hold info about the actual dos rule */
typedef struct {
    char *subrule;
    char *threshold;
    char *timetoblock;
}dosrulestruct;

typedef struct dosblock_hits {
    apr_time_t t;
    apr_int64_t counter;
}dosblock_hits;

typedef struct dosblock_status {
    apr_time_t t;
    int isblocked;
    int rate_when_blocked;
}dosblock_status;

/* Data structure for shared memory block */
typedef struct dosblockipc_data {
    dosblock_hits dh[ARSIZE];
    dosblock_status ds;
    int next;
}dosblockipc_data;

dosblockipc_data *base = NULL;

module AP_MODULE_DECLARE_DATA mod_dosblock_module;

/* Set up all our data structs in the pre config phase */
static void * dosblock_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp) {
    dosblock_cfg *cfg = apr_pcalloc(p, sizeof(*cfg));

    if (!cfg)
        return NULL;
    cfg->urlrules = apr_table_make(p, MAXRULE);
    cfg->headerrules = apr_hash_make(p);
    cfg->ruletype = apr_table_make(p, MAXRULE);
    cfg->dosrulemap = apr_table_make(p, MAXRULE);
    cfg->dosrules = apr_hash_make(p);
    cfg->dosrule_shm_map = apr_hash_make(p);
    cfg->dosrule_mutex_map = apr_table_make(p, MAXRULE);

    return cfg;
}

/* Initialise the requisite data structs for our url based dos subrule
 * @param word1 The name of the subrule
 * @param word2 The pattern
 */
static void *dosblock_url_config(cmd_parms *cmd, void *mconfig, char *word1, char *word2) {
    server_rec *s = cmd->server;
    dosblock_cfg *cfg = (dosblock_cfg *)ap_get_module_config(s->module_config, &mod_dosblock_module);

    if(word1 !=NULL && word2 !=NULL)
      {
        /* We test the regexp and populate the table only on success */
        if (ap_pregcomp(cmd->pool, word2, AP_REG_EXTENDED) != NULL )
            {
             apr_table_set(cfg->urlrules, word1, word2);
             apr_table_set(cfg->ruletype, word1, RULEURL);
            }
        else {
             ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to compile regexp %s", word2);
            }
      }

    return NULL;
}

/* Initialise the requisite data structs for our header based dos subrule
 * @param word1 The name of the subrule
 * @param word2 The http header to match
 * @paramm word3 The pattern
 */
static void *dosblock_header_config(cmd_parms *cmd, void *mconfig, char *word1, char *word2, char *word3) {

    server_rec *s = cmd->server;
    dosblock_cfg *cfg = (dosblock_cfg *)ap_get_module_config(s->module_config, &mod_dosblock_module);

    if(word1 !=NULL && word2 !=NULL && word3 !=NULL)
     {
       headerrulestruct *h = NULL;
       h = apr_palloc(cmd->pool, sizeof(headerrulestruct));
       h->headername = word2;
       h->headerpattern = word3;

       /* We test the regexp and populate the table,hash only on success */
       if (ap_pregcomp(cmd->pool, word3, AP_REG_EXTENDED) != NULL )
          {
           apr_hash_set(cfg->headerrules, word1, APR_HASH_KEY_STRING, h);
           apr_table_set(cfg->ruletype, word1, RULEHEADER);
          }
       else {
           ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to compile regexp %s", word3);
       }

     }
    return NULL;
}

/* Initialise the requisite data structs for the real dos rule
 * @param word1 The "dos rule name: subrule" format
 * @param word2 The threshold rate
 * @param word3 Time (epoch) till blockage
 * */
static void *dosblockrule_config(cmd_parms *cmd, void *mconfig, char *word1, char *word2, char *word3) {
    server_rec *s = cmd->server;
    char  *dosrulename, *subrule, *saveptr1;
    dosblock_cfg *cfg = (dosblock_cfg *)ap_get_module_config(s->module_config, &mod_dosblock_module);

    if(word1 !=NULL && word2 !=NULL && word3 !=NULL)
      {
       dosrulename = apr_strtok(word1, ":", &saveptr1);
       subrule = apr_strtok(NULL, ":", &saveptr1);
       dosrulestruct *d = NULL;
       d = apr_palloc(cmd->pool, sizeof(dosrulestruct));
       d->subrule = subrule;
       d->threshold = word2;
       d->timetoblock = word3;
       /* apr_table_set ensures that the same rule is over-written, while for
        * apr_hash_set we employ the following hack
        */
       apr_table_set(cfg->dosrulemap, dosrulename, subrule);
       if (apr_hash_get(cfg->dosrules, dosrulename, APR_HASH_KEY_STRING) != NULL) {
         /* There is an entry. Delete it. This is a hack so that we only store
          * the latest entry of the same rule
          */
            apr_hash_set(cfg->dosrules, dosrulename, APR_HASH_KEY_STRING, NULL);

        }
       apr_hash_set(cfg->dosrules, dosrulename, APR_HASH_KEY_STRING, d);
     }
    return NULL;
}

/* Set the verbosity flag
 */
static const char *dosblock_verbosityflag(cmd_parms *cmd, void *mconfig, int bool) {
    server_rec *s = cmd->server;
    dosblock_cfg *cfg = (dosblock_cfg *)ap_get_module_config(s->module_config, &mod_dosblock_module);
    cfg->verbosity = bool;
    return NULL;
}

static  command_rec mod_dosblock_cmds[] = {
     AP_INIT_TAKE2("DosBlockUrl", dosblock_url_config, NULL, RSRC_CONF, "Url pattern to look for" ),
     AP_INIT_TAKE3("DosBlockHeader", dosblock_header_config, NULL, RSRC_CONF, "Header pattern to look for" ),
     AP_INIT_TAKE3("DosBlockRule", dosblockrule_config, NULL, RSRC_CONF, "Actual dos rule" ),
     AP_INIT_FLAG("DosBlockVerbose", dosblock_verbosityflag, NULL, RSRC_CONF, "Sets the verbosity flag" ),

    { NULL }
};

/*
 * Clean up the shared memory blocks. This function is registered as
 * cleanup function for the configuration pool, which gets called
 * on restarts. It assures that the new children will not talk to a stale
 * shared memory segments.
 */
static apr_status_t shm_cleanup_wrapper() {
    int i;

    for (i=0; i<MAXRULE; i++) {
       if (dosblockipc_shm[i]) {
       apr_shm_destroy((apr_shm_t *)dosblockipc_shm[i]);
       }
    }
    return OK;
}


/* Merge vserver configs */
static void *dosblock_config_server_merge(apr_pool_t *p, void *base_, void *vhost_) {

     /* We do not support vhosts. The module configs are in the main apache conf */
     return base_;
}

/*
 * This routine is called in the parent, so we'll set up the shared
 * memory segments and mutexs here.
 */
static int dosblock_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    void *data; /* These two help ensure that we only init once. */
    const char *userdata_key;
    apr_status_t rs;
    const char *tempdir;
    dosblockipc_data *base;
    dosblock_cfg *cfg = (dosblock_cfg *)ap_get_module_config(s->module_config, &mod_dosblock_module);
    /*
     * The following checks if this routine has been called before.
     * This is necessary because the parent process gets initialized
     * a couple of times as the server starts up, and we don't want
     * to create any more mutexes and shared memory segments than
     * we're actually going to use.
     *
     * The key needs to be unique for the entire web server, so put
     * the module name in it.
     */
    userdata_key = "dosblock_ipc_init_module";
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);

    if (!data) {
        /*
         * If no data was found for our key, this must be the first
         * time the module is initialized. Put some data under that
         * key and return.
         */
        apr_pool_userdata_set((const void *) 1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    /*
     * The shared memory allocation routines take a file name.
     * Depending on system-specific implementation of these
     * routines, that file may or may not actually be created. We'd
     * like to store those files in the operating system's designated
     * temporary directory, which APR can point us to.
     */
    rs = apr_temp_dir_get(&tempdir, pconf);
    if (APR_SUCCESS != rs) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rs, s,
                     "Failed to find temporary directory");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Create the shared memory segments. We also populate a dosrule to shared
     * memory mapping table with all the shared memory segments
     */

    const apr_array_header_t *tarr = apr_table_elts(cfg->dosrulemap);
    const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
    int i;

    for (i = 0; i < tarr->nelts; ++i) {
     /*
      * Create a unique filename using our pid. This information is
      * stashed in the global variable so the children inherit it.
      */
       shmfilename = apr_psprintf(pconf, "%s/httpd_shm_%s.%ld", tempdir,
                               telts[i].key, (long int)getpid());
       mutex_filename = apr_psprintf(pconf, "%s/httpd_mutex_%s.%ld", tempdir,
                               telts[i].key, (long int)getpid());

       /* Now create that shm segment. We prefer anonymous shm */
       rs = apr_shm_create(&dosblockipc_shm[i], sizeof(dosblockipc_data),
                        NULL, pconf);
       if (APR_ENOTIMPL == rs) {
         rs = apr_shm_create(&dosblockipc_shm[i], sizeof(dosblockipc_data),
                        (const char *) shmfilename, pconf);
         }
       if (APR_SUCCESS != rs) {
           ap_log_error(APLOG_MARK, APLOG_ERR, rs, s,
                       "Failed to create shared memory segment on file %s",
                       shmfilename);
           return HTTP_INTERNAL_SERVER_ERROR;
       }
       apr_hash_set(cfg->dosrule_shm_map, telts[i].key, APR_HASH_KEY_STRING, apr_psprintf(pconf, "%d",i));
       if (cfg->verbosity)
          ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Dos Rule configured is %s", telts[i].key);

       base = (dosblockipc_data *)apr_shm_baseaddr_get(dosblockipc_shm[i]);
       /* Now initialise the array of structs. Zero it out */
       base->ds.t = 0;
       base->ds.isblocked = 0;
       base->ds.rate_when_blocked = 0;
       base->next = 0;
       int j;
       for (j=0; j<ARSIZE; j++) {
         base->dh[j].t = 0;
         base->dh[j].counter = 0;

       }
       /* Create global mutex */

       rs = apr_global_mutex_create(&dosblockipc_mutex[i], mutex_filename, APR_LOCK_DEFAULT, pconf);
      if (APR_SUCCESS != rs) {
          return HTTP_INTERNAL_SERVER_ERROR;
       }
       #ifdef AP_NEED_SET_MUTEX_PERMS
          rs = unixd_set_global_mutex_perms(dosblockipc_mutex[i]);
          if (rs != APR_SUCCESS) {
              ap_log_error(APLOG_MARK, APLOG_CRIT, rs, s,
                 "mod_dosblock: Parent could not set permissions "
                 "on shared memory; check User and Group directives");
              return rs;
           }
       #endif

      apr_table_set(cfg->dosrule_mutex_map, telts[i].key, mutex_filename);

    }
    /*
     * Destroy the shm segment when the configuration pool gets destroyed. This
     *happens on server restarts. The parent will then (above) allocate a new
     * shm segment that the new children will bind to.
     */

    /*
     apr_pool_cleanup_register(pconf, NULL, shm_cleanup_wrapper(),
                              apr_pool_cleanup_null);
    */
     return OK;
}

/*
 * This routine gets called when a child inits. We use it to attach
 * to the shared memory segments, and reinitialize the corresponding mutex.
 */
static void dosblock_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rs ;
    const apr_table_entry_t *dosrule_mutex_map_elts = NULL;
    const apr_array_header_t *dosrule_mutex_map_arr = NULL;
    /*
     * Re-open the mutexes for the child. Note we're reusing
     * the mutex pointer global here.
     */
     dosblock_cfg *cfg = (dosblock_cfg *)ap_get_module_config(s->module_config, &mod_dosblock_module);
     dosrule_mutex_map_arr = apr_table_elts(cfg->dosrule_mutex_map);

     if (dosrule_mutex_map_arr) {
         dosrule_mutex_map_elts = (const apr_table_entry_t *)dosrule_mutex_map_arr->elts;
         int i = 0;
         for (i=0; i<dosrule_mutex_map_arr->nelts; ++i)
           {
            rs = apr_global_mutex_child_init(&dosblockipc_mutex[i], dosrule_mutex_map_elts[i].val, p);
            if (APR_SUCCESS != rs) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rs, s,
                         "Failed to reopen mutex %s in child",
                         dosblockipc_mutex[i]);
                /* There's really nothing else we can do here, since This
                 * routine doesn't return a status. If this ever goes wrong,
                 * it will turn Apache into a fork bomb. Let's hope it never
                 * will.
                */
               exit(1); /* Ugly, but what else? */
             }
          }
     }
}

/* Here-in lies the meat */
static int dosblock_main(request_rec *r) {
    const apr_table_entry_t *dosrulemap_elts = NULL;
    const apr_array_header_t *dosrulemap_arr = NULL;
    char *subrule=NULL, *dosrulematch=NULL, *urlpattern=NULL;
    char *req_header = NULL;
    int matchfound = 0;
    int gotlock = 0;
    dosblockipc_data *base = NULL;
    apr_status_t rs;
    dosblock_cfg *cfg = (dosblock_cfg *)ap_get_module_config(r->server->module_config, &mod_dosblock_module);

    /* Here we try to find if the request matches a dos rule */
    dosrulemap_arr = apr_table_elts(cfg->dosrulemap);

    if (dosrulemap_arr) {
        dosrulemap_elts = (const apr_table_entry_t *)dosrulemap_arr->elts;
        int i;
        for (i=0; i<dosrulemap_arr->nelts; ++i)
         {
           subrule = dosrulemap_elts[i].val;
           char *subrule_type =  (char *)apr_table_get(cfg->ruletype, subrule);
           if (subrule_type == NULL)
             continue;
           /* Check if it is a url based subrule */
           if (0 == apr_strnatcmp(subrule_type, RULEURL))
              {
               urlpattern = (char *)apr_table_get(cfg->urlrules, subrule);
               if (urlpattern == NULL)
                 continue;
               ap_regex_t *pattern = ap_pregcomp(r->pool, urlpattern, AP_REG_EXTENDED);
               if (0 == ap_regexec(pattern, r->uri, 0, NULL, 0))
               /* This is where the dos url subrule would match */
                 {
                   dosrulematch = dosrulemap_elts[i].key;
                   matchfound = 1;
                   break;
                 }
              }
           /* Check if it is a header based subrule */
            else if (0 == apr_strnatcmp(subrule_type, RULEHEADER))
             {
              headerrulestruct *h = NULL;
              h = apr_hash_get(cfg->headerrules, subrule, APR_HASH_KEY_STRING);
              if (h == NULL)
                continue;
              req_header = (char *)apr_table_get(r->headers_in, h->headername);
              if (req_header == NULL)
                continue;
              ap_regex_t *pattern = ap_pregcomp(r->pool, h->headerpattern, AP_REG_EXTENDED);
              if (0 == ap_regexec(pattern, req_header, 0, NULL, 0))
               /* This is where the dos header subrule would match */
                {
                  dosrulematch = dosrulemap_elts[i].key;
                  matchfound = 1;
                  break;
                }
             }
         }
       }

    if (matchfound && dosrulematch) {
      int blocked = 0;
      /* apr_table_set(r->headers_out, "DOSRULE_MATCHED", dosrulematch);*/
      /*  Check if we have the corresponding shared memory segment for
       *  the matching dos rule. If not we do not go further.
       */
      if (!apr_hash_get(cfg->dosrule_shm_map, dosrulematch, APR_HASH_KEY_STRING))
       {
          return DECLINED;
        }
      apr_int64_t index = apr_atoi64(apr_hash_get(cfg->dosrule_shm_map, dosrulematch, APR_HASH_KEY_STRING));

      /* Take the mutex lock here. Be careful of not 'returning' before releasing the lock*/
      rs = apr_global_mutex_lock(dosblockipc_mutex[index]);
      if (APR_SUCCESS == rs) {
          gotlock = 1;
      }
      else {
        /* Some error, log and bail */
        ap_log_error(APLOG_MARK, APLOG_ERR, rs, r->server, "Child %ld failed to acquire lock", (long int)getpid());
      }
      base = (dosblockipc_data *)apr_shm_baseaddr_get(dosblockipc_shm[index]);
      /* check if the Dos rule is already blocked */
      if (base->ds.isblocked)
       {
        /* The dos rule is blocked at this moment. Need to check the time stamp
         * (time till blockage) and act accordingly
         */
        apr_time_t time_now = apr_time_now();
        apr_time_t time_to_blockage = base->ds.t;
        /* apr_table_set(r->headers_out, "Blocked till", apr_psprintf(r->pool, "%d",time_to_blockage)); */
        if(cfg->verbosity)
           ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Dos rule %s is blocked", dosrulematch);
        if (time_now < time_to_blockage)
         {
          /* Keep blocking */
           blocked = 1;
           if(cfg->verbosity)
             ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Keep dos rule %s blocked", dosrulematch);

         }
        else {
          /* Time to unblock */
           base->ds.isblocked = 0;
           base->ds.t = 0;
           /* apr_table_set(r->headers_out, "Time-to-unblock", "Unblock"); */
           if(cfg->verbosity)
             ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Time to unblock dos rule %s", dosrulematch);

          }
      }
      /* Here we age entries, try to account for the matched hit, calculate the
       * rate and take some action if needed.
       */
      int i;
      apr_int64_t sum_counter = 0;
      int hit_accounted = 0;

      /* Loop through the array of structs */
      for (i=0; i<ARSIZE; i++) {
        if (base->dh[i].t) {
          if ((r->request_time - base->dh[i].t)/APR_USEC_PER_SEC > ARSIZE ) {
            /* Ageing entries */
             base->dh[i].t = 0;
             base->dh[i].counter = 0;
             if(cfg->verbosity)
               ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Ageing entry for dos rule %s", dosrulematch);
             continue;
           }
          if (base->dh[i].t/APR_USEC_PER_SEC == r->request_time/APR_USEC_PER_SEC )
            {
              /* There is already an entry for this sec. Increment the corresponding
               * counter
               */
              base->dh[i].counter++;
              sum_counter+= base->dh[i].counter;
              hit_accounted = 1;
              /*apr_table_set(r->headers_out, "Entry-for-this-sec", "Exists"); */
              if(cfg->verbosity)
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "We have an Entry-for-this-sec for dos rule %s", dosrulematch);
             continue;
            }
          sum_counter+= base->dh[i].counter;
          }
        }

      /* Add an element in our array of structs for this second if the hit was not accounted above */
      if (! hit_accounted) {
        if(cfg->verbosity)
          ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Hit is not accounted for dos rule %s", dosrulematch);
        if ((ARSIZE - base->next) ==  0)
          base->next = 0;
        base->dh[base->next].t = r->request_time;
        base->dh[base->next].counter = 1;
        sum_counter+= base->dh[base->next].counter;
        base->next++;
        /*apr_table_set(r->headers_out, "Entry-for-this-sec", "Does-not-Exist");*/
        if(cfg->verbosity)
          ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "We do not have an entry for this second (dos rule %s) and sum of counter is %" APR_INT64_T_FMT, dosrulematch, sum_counter);
      }

      if ( ! blocked) {
        float rate = (float)sum_counter/ARSIZE;
        /* Get the configured rate threshold */
        dosrulestruct *d = apr_hash_get(cfg->dosrules, dosrulematch, APR_HASH_KEY_STRING);
        if(cfg->verbosity) {
          ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Non Blocked dos rule %s sum of counter is %" APR_INT64_T_FMT, dosrulematch, sum_counter);
          ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Non Blocked dos rule %s rate is %f", dosrulematch, rate);
          ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Non Blocked dos rule %s configured  rate is %" APR_INT64_T_FMT, dosrulematch, apr_atoi64(d->threshold));
        }
        if (rate > apr_atoi64(d->threshold))
         {
           /* Block it */
           base->ds.isblocked = 1;
           base->ds.t = (apr_time_now() + (apr_atoi64(d->timetoblock)*APR_USEC_PER_SEC));
           base->ds.rate_when_blocked = rate;
           if(cfg->verbosity) {
             ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Non Blocked dos rule %s getting blocked after rate calulation", dosrulematch);
             ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Non Blocked dos rule %s getting blocked till %" APR_TIME_T_FMT, dosrulematch, base->ds.t);
           }
           blocked = 1;
         }
      }

      /* Release the lock. We have to be careful of not 'returning' before
       * releasing the lock
       */
      if (gotlock)
        rs = apr_global_mutex_unlock(dosblockipc_mutex[index]);
      /* Swallowing the result because what are we going to do with it at
       * this stage
       */
      if (blocked)
        return HTTP_FORBIDDEN;
   }
    else {
      /* apr_table_set(r->headers_out, "DOSRULE_MATCHED", "None");*/
    }

    return DECLINED;
}

static void register_hooks(apr_pool_t *p) {
   ap_hook_post_config(dosblock_post_config, NULL, NULL, APR_HOOK_MIDDLE);
   ap_hook_child_init(dosblock_child_init, NULL, NULL, APR_HOOK_MIDDLE);
   ap_hook_post_read_request(dosblock_main, NULL, NULL, APR_HOOK_FIRST);

}

module AP_MODULE_DECLARE_DATA mod_dosblock_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                         /* create per-directory config structure */
    NULL,                         /* merge per-directory config structures */
    dosblock_config,              /* create per-server config structure */
    dosblock_config_server_merge, /* merge per-server config structures */
    mod_dosblock_cmds,            /* command table */
    register_hooks
};
