#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>

extern int	ipfw2_table_no;
int		table_handler(int ac, char *av[]);

int 
process_record(char *host, unsigned int exptime)
{
	int		rc = 0;
	int		argc = 4;
	char		mode      [] = "table";
	char		table     [100] = "";
	char		command   [] = "delete";
	char          **argv;

	snprintf(table, sizeof(table), "%d", ipfw2_table_no);
	argv = calloc(argc, sizeof(char *));

	argv[0] = mode;
	argv[1] = table;
	argv[2] = command;
	argv[3] = host;

	if (time(NULL) > exptime) {

		syslog(LOG_INFO, "Removing host %s from table %d",
		       host, ipfw2_table_no);
		rc = table_handler(argc, argv);
	}
	free(argv);
	return 0;
}
