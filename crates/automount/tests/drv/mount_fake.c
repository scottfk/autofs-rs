/*
 * mount_fake.c - a recording mount module, built as each mount_NAME.so for the C driver
 *
 * 20261127 - Created by Claude (claude.ai, Anthropic) - scottfk
 *
 * Built with -DMODNAME=\"NAME\". Logs what it's asked to do to stderr, in the
 * format of the port's FakeMount (src/daemon/module.rs), and succeeds.
 */

#include <stdio.h>

#define MODULE_MOUNT
#include "automount.h"

int mount_version = AUTOFS_MOUNT_VERSION;

static const char *s(const char *p)
{
	return p ? p : "(null)";
}

int mount_init(void **context)
{
	fprintf(stderr, "fake mount(%s): init\n", MODNAME);
	*context = NULL;
	return 0;
}

int mount_reinit(void **context)
{
	(void) context;
	return 0;
}

int mount_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context)
{
	(void) ap; (void) name_len; (void) context;
	fprintf(stderr, "fake mount(%s): root=%s name=%s what=%s fstype=%s options=%s\n",
		MODNAME, s(root), s(name), s(what), s(fstype), s(options));
	return 0;
}

int mount_done(void *context)
{
	(void) context;
	fprintf(stderr, "fake mount(%s): done\n", MODNAME);
	return 0;
}
