#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <strings.h>
#include <string.h>
#include <sysexits.h>
#include <stdlib.h>
#include <err.h>
#include <pcre.h>
#include <syslog.h>

#include "iniparse/iniparser.h"

#define MAXHOSTS 5000
#define BUFFER_SIZE 30000
#define OVECCOUNT 30		/* should be a multiple of 3 */

typedef struct {
	int		count;
	time_t		access_time;
	char		ipaddr    [300];
}		hosts;

hosts		hosts_table[MAXHOSTS];

int		table_handler(int ac, char *av[]);

int		process_record(char *host, unsigned int reset_ip);

int		max_count = -1;
int		within_time = -1;
int		ipfw2_table_no = -1;
int		reset_ip = -1;


static void 
usage()
{
	fprintf(stderr,
	"\n"
	"Usage: bruteblock -f config_file\n"
	"       -f          pathname of the configuration file\n"
	"       -h          print this message.\n" "\n");
	exit(EX_USAGE);
}


static int 
add_host(char *host)
{
	int		i;
	
	for (i = 0; i < MAXHOSTS; i++) {
		/* find empty record */
		if (hosts_table[i].count == 0) {
			hosts_table[i].count = 1;
			hosts_table[i].access_time = time(NULL);
			strncpy(hosts_table[i].ipaddr, host,
			sizeof(hosts_table[i].ipaddr));
			return 0;
		}
	}
	/* table is full! */
	return 1;
}


static int 
check_host(char *host)
{
	
	char		mode      [] = "table";
	char		command   [] = "add";
	char		table     [200] = "";
	char		utime     [200] = "";
	char          **argv;
	int		argc = 5;
	int		rc;
	int		i;
	int		curtime = time(NULL);
	
	snprintf(table, sizeof(table), "%d", ipfw2_table_no);
	for (i = 0; i < MAXHOSTS; i++) {
		/* skip empty sets */
		if (!hosts_table[i].count)
			continue;
		/* cleanup expired hosts */ 
		if (hosts_table[i].access_time + within_time < curtime) {
			hosts_table[i].count = 0;
			continue;
		}
		/* host in the hosts table */
		if (strcmp(host, hosts_table[i].ipaddr) == 0) {
			hosts_table[i].count++;
			if (hosts_table[i].count == max_count) {
				argv = calloc(argc, sizeof(char *));
				argv[0] = mode;
				snprintf(table, sizeof(table), "%d", ipfw2_table_no);
				argv[1] = table;
				argv[2] = command;
				snprintf(utime, sizeof(utime), "%lld",
				(long long)(time(NULL) + reset_ip));
				argv[4] = utime;
				argv[3] = host;
				
				syslog(LOG_INFO, "Adding %s to the ipfw table %d", host, ipfw2_table_no);
				rc = table_handler(argc, argv);
				if (rc)
					syslog(LOG_ERR, "Adding %s to table %d failed, rc=%d",
				host, ipfw2_table_no, rc);
				else
					free(argv);
			} else if (hosts_table[i].count > max_count) {
				syslog(LOG_NOTICE, "Blocking failed for %s",
				host);
			}
			return 1;
		}
	}
	return 0;
}

void 
print_table()
{
	int		i;
	for (i = 0; i < MAXHOSTS; i++) {
		/* skip empty sets */
		if (hosts_table[i].count) {
			printf("table: ip=%s,count=%d,time=%d\n",
			hosts_table[i].ipaddr, hosts_table[i].count,
			hosts_table[i].access_time);
		}
	}
	
}

int 
main(int ac, char *av[])
{
	char		hostaddr  [255];
	char           *hostaddprp = hostaddr;
	bzero(hosts_table, sizeof(hosts_table));
	int		ch        , done = 0, rc,i,k,matches=0;
	FILE           *infile = stdin;
	pcre           *re[11]; /* up to 1+10 regular expressions can be used */
	int		re_count =  1;
	const char     *error;
	int		erroffset;
	int		ovector    [OVECCOUNT];
	char           *regexp;
	unsigned char  *buffer;
	dictionary     *ini;
	char		config_path[PATH_MAX];
	char           *config_pathp = config_path;
	
	buffer = (unsigned char *)malloc(BUFFER_SIZE);
	
	if (ac < 2) {
		usage();
	}
	while ((ch = getopt(ac, av, "f:h")) != -1) {
		switch (ch) {
			
			case 'f':	/* config file */
			strncpy(config_pathp, optarg, sizeof(config_path));
			break;
			case '?':
			default:
			usage();
		}
	}
	
	ac -= optind;
	av += optind;
	
	openlog("bruteblock", LOG_PID | LOG_NDELAY, LOG_AUTH);
	/* Reading configutation file */
	ini = iniparser_load(config_path);
	if (!ini) {
		syslog(LOG_ALERT, "Cannot parse configuration file \"%s\"", config_path);
		exit(EX_CONFIG);
	}
	regexp = iniparser_getstr(ini, ":regexp");
	if (!regexp) {
		syslog(LOG_ALERT, "Configuration error - 'regexp' key not found in \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	
	
	max_count = iniparser_getint(ini, ":max_count", -1);
	if (max_count < 0) {
		syslog(LOG_ALERT, "Configuration error - 'max_count' key not found in \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	within_time = iniparser_getint(ini, ":within_time", -1);
	if (within_time < 0) {
		syslog(LOG_ALERT, "Configuration error - 'within_time' key not found in \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	ipfw2_table_no = iniparser_getint(ini, ":ipfw2_table_no", -1);
	if (ipfw2_table_no < 0) {
		syslog(LOG_ALERT, "Configuration error - 'ipfw2_table_no' key not found in \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	reset_ip = iniparser_getint(ini, ":reset_ip", -1);
	if (reset_ip < 0) {
		syslog(LOG_ALERT, "Configuration error - 'reset_ip' key not found in \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	
	re[0] = pcre_compile(
	regexp,	/* the pattern */
	PCRE_CASELESS,	/* case insensitive match */
	&error,	/* for error message */
	&erroffset,	/* for error offset */
	NULL);/* use default character tables */
	if (re[0] == NULL) {
		syslog(LOG_ERR, "PCRE regexp compilation failed at offset %d: %s", erroffset, error);
		exit(EX_SOFTWARE);
	}
	
	/* searching for additonal regexp patterns, e.g. regexp0-regexp1*/
	
	for(i=0;i<10;i++){
		snprintf(buffer, BUFFER_SIZE, ":regexp%d", i);
		regexp = iniparser_getstr(ini, buffer);
		if (regexp) {
  			re[re_count] = pcre_compile(
			regexp,	/* the pattern */
			PCRE_CASELESS,	/* case insensitive match */
			&error,	/* for error message */
			&erroffset,	/* for error offset */
			NULL);/* use default character tables */
			if (re[re_count] == NULL) {
				syslog(LOG_ERR, "PCRE regexp%d compilation failed at offset %d: %s", i,erroffset, error);
				exit(EX_SOFTWARE);
			}
			re_count++;
		}
	}
	
	while (!done) { /* main loop */
		if (fgets((char *)buffer, BUFFER_SIZE, infile) == NULL)
			break;
		for(k=0;k<re_count;k++)	{ /* check string for all regexps */
			rc = pcre_exec(
			re[k],	/* the compiled pattern */
			NULL,	/* no extra data - we didn't study
			* the pattern */
			buffer,	/* the subject string */
			strlen(buffer),	/* the length of the subject */
			0,	/* start at offset 0 in the subject */
			0,	/* default options */
			ovector,	/* output vector for substring
			* information */
			OVECCOUNT);	/* number of elements in the
			* output vector */
			if (rc < 0) {
				switch (rc) {
					case PCRE_ERROR_NOMATCH:
					continue;
					break;
					default:
					syslog(LOG_ERR, "pcre_exec failed: rc=%d", rc);
					continue;
					break;
				}
			}
			for (i = 1; i < rc; i++) 
			{
				char *substring_start = buffer + ovector[2*i];
				int substring_length = ovector[2*i+1] - ovector[2*i];
				if(substring_length){ /* skip "unset" patterns */
					snprintf(hostaddprp, sizeof(hostaddr), "%.*s",
					substring_length, substring_start);
					matches++;
				}
			}
			if (matches == 1){ /* we have ip address to add */
				if (!check_host(hostaddprp)) {
					/* not in table, add */
					add_host(hostaddprp);
				}
				matches = 0;
				break;
			}
			else { /* error in regexp */
				syslog(LOG_ERR, "error: regexp matched %d times!", matches);
				matches = 0;
				break;
			}
		}
		
	}
	for(i=0;i<re_count;i++)	free(re[i]); /* release re memory */
	iniparser_freedict(ini);/* Release memory used for the configuration */
	return EX_OK;
}

