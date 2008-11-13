
#include <glib.h>
#include <gnet.h>
#include <stdint.h>
#include <netinet/in.h>

#include "iscsi.h"
#include "target.h"
#include "parameters.h"

uint32_t iscsi_debug_level = 0;

static GServer *tcp_srv;

static struct globals gbls = {
	.port = 3260,
};

int device_init(struct globals *a, targv_t * b, struct disc_target *c)
{
	return -1;
}

int device_command(struct target_session *e, struct target_cmd *d)
{
	return -1;
}

int device_shutdown(struct target_session *f)
{
	return -1;
}

static void tcp_srv_event(GServer * srv, GConn * conn, gpointer user_data)
{
	target_accept(&gbls, conn);
}

static int net_init(void)
{
	tcp_srv = gnet_server_new(NULL, 3260, tcp_srv_event, NULL);
	if (!tcp_srv)
		return -1;

	return 0;
}

static void net_exit(void)
{
	gnet_server_unref(tcp_srv);
}

static targv_t tv_all[4];

static int master_iscsi_init(void)
{
	return target_init(&gbls, tv_all, "MyFirstTarget");
}

static void master_iscsi_exit(void)
{
	target_shutdown(&gbls);
}

int main(int argc, char *argv[])
{
	GMainLoop *ml;

	ml = g_main_loop_new(NULL, FALSE);
	if (!ml)
		return 1;

	if (net_init())
		return 1;
	if (master_iscsi_init())
		return 1;

	g_main_loop_run(ml);

	master_iscsi_exit();
	net_exit();

	g_main_loop_unref(ml);

	return 0;
}
