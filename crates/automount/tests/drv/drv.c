/*
 * drv.c - test driver: read the master map and the maps as the daemon does, then look keys up
 *
 * 20261127 - Created by Claude (claude.ai, Anthropic) - scottfk
 *
 * Linked with the reference build's daemon objects (automount.o with its
 * main() renamed) and libautofs.so, so every call is the reference's own.
 *
 * Usage: drv [-d] [-v] PATH KEY UID GID [PATH KEY UID GID...]
 *
 * For each master map entry, the maps are read as handle_mounts() would
 * (lookup_nss_read_map(), lookup_prune_cache(), lookup_ghost() when browsing),
 * then each KEY is looked up under the entry for PATH as the request thread
 * would (set_tsd_user_vars(), lookup_nss_mount()). The mount modules are the
 * recorders in mount_fake.c. The Rust driver (src/bin/automount_drv.rs) does
 * the same with the port's code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "automount.h"

extern struct master *master_list;
extern const char *program;
extern pthread_key_t key_thread_stdenv_vars;

static void tsv_destroy(void *arg)
{
	(void) arg;
}

int main(int argc, char **argv)
{
	unsigned int flags = 0;
	struct list_head *p;
	time_t age;
	int i = 1;
	sigset_t sigs;

	sigfillset(&sigs);
	pthread_sigmask(SIG_BLOCK, &sigs, NULL);
	program = argv[0];
	while (i < argc && argv[i][0] == '-') {
		if (!strcmp(argv[i], "-d"))
			set_log_debug(0);
		else if (!strcmp(argv[i], "-v"))
			set_log_verbose();
		i++;
	}
	if (!defaults_read_config(0)) {
		printf("drv: failed to read configuration\n");
		return 1;
	}
	if (defaults_get_browse_mode())
		flags |= DAEMON_FLAGS_GHOST;
	macro_init();
	pthread_key_create(&key_thread_stdenv_vars, tsv_destroy);
	master_list = master_new(NULL, defaults_get_timeout(), flags);
	log_to_stderr();
	master_init_scan();
	master_list->nc = cache_init_null_cache(master_list);
	age = monotonic_time(NULL);
	lookup_nss_read_master(master_list, age);
	list_for_each(p, &master_list->mounts) {
		struct master_mapent *entry = list_entry(p, struct master_mapent, list);
		struct autofs_point *ap = entry->ap;

		printf("drv: entry %s\n", ap->path);
		if (!lookup_nss_read_map(ap, NULL, age))
			printf("drv: failed to read map for %s\n", ap->path);
		lookup_prune_cache(ap, age);
		if (ap->flags & MOUNT_FLAG_GHOST)
			printf("drv: ghost %s -> %#x\n", ap->path, lookup_ghost(ap));
	}
	fflush(stdout);
	for (; i + 3 < argc; i += 4) {
		struct master_mapent *entry = master_find_mapent(master_list, argv[i]);
		int ret;

		if (!entry) {
			printf("drv: no entry %s\n", argv[i]);
			continue;
		}
		set_tsd_user_vars(entry->ap->logopt, atoi(argv[i + 2]), atoi(argv[i + 3]));
		ret = lookup_nss_mount(entry->ap, NULL, argv[i + 1], strlen(argv[i + 1]));
		printf("drv: lookup %s %s -> %d\n", argv[i], argv[i + 1], ret);
		fflush(stdout);
	}
	list_for_each(p, &master_list->mounts) {
		struct master_mapent *entry = list_entry(p, struct master_mapent, list);
		lookup_close_lookup(entry->ap);
	}
	printf("drv: done\n");
	return 0;
}
