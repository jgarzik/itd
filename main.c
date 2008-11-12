
#include <glib.h>
#include <stdint.h>
#include <netinet/in.h>

#include "compat.h"
#include "iscsi.h"
#include "target.h"
#include "device.h"
#include "md5.h"
#include "parameters.h"

uint32_t iscsi_debug_level = 0;

int device_init(globals_t * a, targv_t * b, disc_target_t * c)
{
	return -1;
}

int device_command(target_session_t * e, target_cmd_t * d)
{
	return -1;
}

int device_shutdown(target_session_t * f)
{
	return -1;
}

int main(int argc, char *argv[])
{
	return 0;
}
