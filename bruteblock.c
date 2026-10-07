#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <strings.h>
#include <string.h>
#include <sysexits.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <syslog.h>

#include "iniparse/iniparser.h"

#define MAXHOSTS 5000
#define BUFFER_SIZE 30000

typedef struct {
	int		count;
	time_t		access_time;
	char		ipaddr    [300];
}		hosts;

hosts		hosts_table[MAXHOSTS];

void		ipfw_table_handler(int ac, char *av[]);

int		process_record(char *host, unsigned int reset_ip);

int		max_count = -1;
int		within_time = -1;
int		ipfw2_table_no = -1;
int		reset_ip = -1;
int		ipv6_prefixlen = 64;


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


/*
 * Record a failed attempt for host, adding a new record if needed.
 * Stale records are dropped while scanning. The counter is updated here
 * and the threshold is enforced by check_host() afterwards, so that
 * max_count = 1 also blocks on the very first attempt.
 */
static void
update_host(const char *host)
{
	int		i;
	int		freeslot = -1;
	time_t		curtime = time(NULL);

	for (i = 0; i < MAXHOSTS; i++) {
		/* remember the first reusable record */
		if (hosts_table[i].count == 0) {
			if (freeslot < 0)
				freeslot = i;
			continue;
		}
		/* drop records older than within_time */
		if (hosts_table[i].access_time + within_time < curtime) {
			hosts_table[i].count = 0;
			if (freeslot < 0)
				freeslot = i;
			continue;
		}
		/* host is already tracked, bump the counter */
		if (strcmp(host, hosts_table[i].ipaddr) == 0) {
			hosts_table[i].count++;
			return;
		}
	}

	if (freeslot < 0) {
		syslog(LOG_NOTICE, "Host table is full, cannot track %s", host);
		return;
	}

	hosts_table[freeslot].count = 1;
	hosts_table[freeslot].access_time = time(NULL);
	strncpy(hosts_table[freeslot].ipaddr, host,
	    sizeof(hosts_table[freeslot].ipaddr));
	hosts_table[freeslot].ipaddr[sizeof(hosts_table[freeslot].ipaddr) - 1] = '\0';
}


/*
 * Add host to the ipfw table with an expiration time. Called once the
 * number of attempts reaches max_count.
 */
static void
block_host(const char *host)
{
	char		mode      [] = "table";
	char		command   [] = "add";
	char		table     [200] = "";
	char		utime     [200] = "";
	char          **argv;
	int		argc = 5;

	snprintf(table, sizeof(table), "%d", ipfw2_table_no);
	snprintf(utime, sizeof(utime), "%lld",
	    (long long)(time(NULL) + reset_ip));

	if ((argv = calloc(argc, sizeof(char *))) == NULL) {
		syslog(LOG_ERR, "calloc failed, cannot block %s", host);
		return;
	}
	argv[0] = mode;
	argv[1] = table;
	argv[2] = command;
	argv[3] = (char *)host;
	argv[4] = utime;

	syslog(LOG_INFO, "Adding %s to the ipfw table %d", host, ipfw2_table_no);
	ipfw_table_handler(argc, argv);
	free(argv);
}


/*
 * Enforce the max_count threshold for host. Runs right after
 * update_host(), so the first attempt is evaluated as well.
 */
static void
check_host(const char *host)
{
	int		i;
	time_t		curtime = time(NULL);

	for (i = 0; i < MAXHOSTS; i++) {
		if (hosts_table[i].count == 0)
			continue;
		if (hosts_table[i].access_time + within_time < curtime)
			continue;
		if (strcmp(host, hosts_table[i].ipaddr) != 0)
			continue;
		if (hosts_table[i].count == max_count) {
			block_host(host);
		} else if (hosts_table[i].count > max_count) {
			syslog(LOG_NOTICE, "Host %s already blocked", host);
		}
		return;
	}
}

void 
print_table()
{
	int		i;
	for (i = 0; i < MAXHOSTS; i++) {
		/* skip empty sets */
		if (hosts_table[i].count) {
			printf("table: ip=%s,count=%d,time=%ld\n",
			hosts_table[i].ipaddr, hosts_table[i].count,
			hosts_table[i].access_time);
		}
	}
	
}

/*
 * Convert an address extracted from a log line into an ipfw table key.
 *
 * IPv4 addresses are used as-is to preserve the existing behaviour.
 * IPv6 addresses are masked down to ipv6_prefixlen, so that an attacker
 * cannot evade blocking by rotating through addresses within its own
 * prefix. The resulting key is either an IPv6 address ("2001:db8::1")
 * when ipv6_prefixlen is 128, or a network in CIDR notation
 * ("2001:db8:1:2::/64") otherwise.
 *
 * Returns 0 on success, -1 if the string is not a valid IP address.
 */
static int
normalize_host(const char *host, char *out, size_t outsize)
{
	struct in_addr	a4;
	struct in6_addr	a6;
	char		buf[INET6_ADDRSTRLEN];
	int		i, plen;

	if (inet_pton(AF_INET, host, &a4) == 1) {
		/* Keep IPv4 handling untouched */
		if (strlcpy(out, host, outsize) >= outsize)
			return -1;
		return 0;
	}

	if (inet_pton(AF_INET6, host, &a6) != 1)
		return -1;

	/* ::ffff:a.b.c.d is really an IPv4 address */
	if (IN6_IS_ADDR_V4MAPPED(&a6)) {
		struct in_addr mapped;

		memcpy(&mapped, &a6.s6_addr[12], sizeof(mapped));
		if (inet_ntop(AF_INET, &mapped, buf, sizeof(buf)) == NULL)
			return -1;
		if (strlcpy(out, buf, outsize) >= outsize)
			return -1;
		return 0;
	}

	/* Zero out the bits outside of the configured prefix */
	plen = ipv6_prefixlen;
	for (i = 0; i < 16; i++) {
		if (plen >= 8) {
			plen -= 8;
			continue;
		}
		if (plen > 0)
			a6.s6_addr[i] &= (uint8_t)(0xff << (8 - plen));
		else
			a6.s6_addr[i] = 0;
		plen = 0;
	}

	if (inet_ntop(AF_INET6, &a6, buf, sizeof(buf)) == NULL)
		return -1;

	if (ipv6_prefixlen < 128)
		snprintf(out, outsize, "%s/%d", buf, ipv6_prefixlen);
	else
		snprintf(out, outsize, "%s", buf);

	return 0;
}

int 
main(int ac, char *av[])
{
	char		hostaddr  [255];
	char           *hostaddprp = hostaddr;
	char		normalized[INET6_ADDRSTRLEN + 8];
	bzero(hosts_table, sizeof(hosts_table));
	int ch, done = 0, i, k, matches = 0;
	FILE           *infile = stdin;
	pcre2_code *re[11]; /* up to 1+10 regular expressions can be used */
	int		re_count =  1;
    int errornumber;
    PCRE2_SIZE erroffset;
    uint32_t options = PCRE2_CASELESS;
    pcre2_match_data *match_data[11];
    PCRE2_SIZE *ovector;
	char           *regexp;
	PCRE2_SPTR buffer;
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
	/* IPv6 addresses are aggregated to this prefix length, default /64 */
	ipv6_prefixlen = iniparser_getint(ini, ":ipv6_prefixlen", 64);
	if (ipv6_prefixlen < 0 || ipv6_prefixlen > 128) {
		syslog(LOG_ALERT, "Configuration error - 'ipv6_prefixlen' must be between 0 and 128 in \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	
    re[0] = pcre2_compile(
        (PCRE2_SPTR)regexp,    /* the pattern */
        PCRE2_ZERO_TERMINATED, /* length of the pattern */
        options,               /* options */
        &errornumber,         /* for error number */
        &erroffset,           /* for error offset */
        NULL);                /* use default compile context */

	if (re[0] == NULL) {
        PCRE2_UCHAR error_buffer[256];
        pcre2_get_error_message(errornumber, error_buffer, sizeof(error_buffer));
        syslog(LOG_ERR, "PCRE2 regexp compilation failed at offset %d: %s", 
               (int)erroffset, (char *)error_buffer);
		exit(EX_SOFTWARE);
	}

    match_data[0] = pcre2_match_data_create_from_pattern(re[0], NULL);
	
	/* searching for additonal regexp patterns, e.g. regexp0-regexp1*/
	
	for(i=0;i<10;i++){
        char pattern_key[BUFFER_SIZE];
        snprintf(pattern_key, BUFFER_SIZE, ":regexp%d", i);
        regexp = iniparser_getstr(ini, pattern_key);
		if (regexp) {
            re[re_count] = pcre2_compile(
                (PCRE2_SPTR)regexp,    /* the pattern */
                PCRE2_ZERO_TERMINATED, /* length of the pattern */
                options,               /* options */
                &errornumber,         /* for error number */
                &erroffset,           /* for error offset */
                NULL);                /* use default compile context */
			if (re[re_count] == NULL) {
                PCRE2_UCHAR error_buffer[256];
                pcre2_get_error_message(errornumber, error_buffer, sizeof(error_buffer));
                syslog(LOG_ERR, "PCRE2 regexp%d compilation failed at offset %d: %s", 
                       i, (int)erroffset, (char *)error_buffer);
				exit(EX_SOFTWARE);
			}
			match_data[re_count] = pcre2_match_data_create_from_pattern(re[re_count], NULL);
			re_count++;
		}
	}
	
	while (!done) { /* main loop */
		if (fgets((char *)buffer, BUFFER_SIZE, infile) == NULL)
			break;
		for(k=0;k<re_count;k++)	{ /* check string for all regexps */
            int rc = pcre2_match(
                re[k],                  /* the compiled pattern */
                buffer,                 /* the subject string */
                strlen((char *)buffer), /* the length of the subject */
                0,                      /* start at offset 0 in the subject */
                0,                      /* default options */
                match_data[k],          /* block for storing the result */
                NULL);                  /* use default match context */
			if (rc < 0) {
				switch (rc) {
					case PCRE2_ERROR_NOMATCH:
					continue;
					break;
					default:
					syslog(LOG_ERR, "pcre2_match failed: rc=%d", rc);
					continue;
					break;
				}
			}
			ovector = pcre2_get_ovector_pointer(match_data[k]);
			for (i = 1; i < rc; i++) 
			{
				PCRE2_SIZE substring_length = ovector[2*i+1] - ovector[2*i];
				if(substring_length){ /* skip "unset" patterns */
					snprintf(hostaddprp, sizeof(hostaddr), "%.*s",
					(int)substring_length, (char *)(buffer + ovector[2*i]));
					matches++;
				}
			}
			if (matches == 1){ /* we have ip address to add */
				if (normalize_host(hostaddprp, normalized,
				    sizeof(normalized)) != 0) {
					syslog(LOG_WARNING, "Ignoring invalid address \"%s\"",
					hostaddprp);
					matches = 0;
					break;
				}
				/* record the attempt and enforce max_count */
				update_host(normalized);
				check_host(normalized);
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
    /* Cleanup */
    for(i = 0; i < re_count; i++) {
        pcre2_match_data_free(match_data[i]);
        pcre2_code_free(re[i]);
    }
	iniparser_freedict(ini);/* Release memory used for the configuration */
	free((void *)buffer);
	return EX_OK;
}

