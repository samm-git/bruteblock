/*
 * Copyright (c) 2002-2003 Luigi Rizzo Copyright (c) 1996 Alex Nash, Paul
 * Traina, Poul-Henning Kamp Copyright (c) 1994 Ugen J.S.Antsilevich
 * 
 * Idea and grammar partially left from: Copyright (c) 1993 Daniel Boulet
 * 
 * Redistribution and use in source forms, with and without modification, are
 * permitted provided that this entire comment appears intact.
 * 
 * Redistribution in binary form may occur without any restrictions. Obviously,
 * it would be nice if you gave credit where credit is due but requiring it
 * would be too onerous.
 * 
 * This software is provided ``AS IS'' without any warranties of any kind.
 * 
 * NEW command line interface for IP firewall facility
 * 
 * Copyright (c) 2006 Alex Samorukov, bruteblock
 */

#include <sys/socket.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/ip_fw.h>
#include <arpa/inet.h>

#define NEED1(msg)      {if (!ac) errx(EX_USAGE, msg);}

int		process_record(char *host, unsigned int exptime);
#define	TABLEARG	"tablearg"

/*
 * conditionally runs the command.
 */
static int
do_cmd(int optname, void *optval, uintptr_t optlen)
{
	static int	s = -1;	/* the socket */
	int		i;

	if (s == -1)
		s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s < 0)
		err(EX_UNAVAILABLE, "socket");

	if (optname == IP_FW_GET || optname == IP_DUMMYNET_GET ||
	    optname == IP_FW_ADD || optname == IP_FW_TABLE_LIST ||
	    optname == IP_FW_TABLE_GETSIZE)
		i = getsockopt(s, IPPROTO_IP, optname, optval,
			       (socklen_t *) optlen);
	else
		i = setsockopt(s, IPPROTO_IP, optname, optval, optlen);
	return i;
}


/*
 * _substrcmp takes two strings and returns 1 if they do not match, and 0 if
 * they match exactly or the first string is a sub-string of the second.  A
 * warning is printed to stderr in the case that the first string is a
 * sub-string of the second.
 * 
 * This function will be removed in the future through the usual deprecation
 * process.
 */
static int
_substrcmp(const char *str1, const char *str2)
{

	if (strncmp(str1, str2, strlen(str1)) != 0)
		return 1;

	if (strlen(str1) != strlen(str2))
		warnx("DEPRECATED: '%s' matched '%s' as a sub-string",
		      str1, str2);
	return 0;
}

static int
lookup_host(char *host, struct in_addr *ipaddr)
{
	struct hostent *he;

	if (!inet_aton(host, ipaddr)) {
		if ((he = gethostbyname(host)) == NULL)
			return (-1);
		*ipaddr = *(struct in_addr *)he->h_addr_list[0];
	}
	return (0);
}

/*
 * This one handles all table-related commands ipfw table N add
 * addr[/masklen] [value] ipfw table N delete addr[/masklen] ipfw table N
 * flush ipfw table N list
 */
int
table_handler(int ac, char *av[])
{
	ipfw_table_entry ent;
	ipfw_table     *tbl;
	int		do_add;
	char           *p;
	socklen_t	l;
	uint32_t	a;

	ac--;
	av++;
	if (ac && isdigit(**av)) {
		ent.tbl = atoi(*av);
		ac--;
		av++;
	} else
		errx(EX_USAGE, "table number required");
	NEED1("table needs command");
	if (_substrcmp(*av, "add") == 0 ||
	    _substrcmp(*av, "delete") == 0) {
		do_add = **av == 'a';
		ac--;
		av++;
		if (!ac)
			errx(EX_USAGE, "IP address required");
		p = strchr(*av, '/');
		if (p) {
			*p++ = '\0';
			ent.masklen = atoi(p);
			if (ent.masklen > 32)
				errx(EX_DATAERR, "bad width ``%s''", p);
		} else
			ent.masklen = 32;
		if (lookup_host(*av, (struct in_addr *)&ent.addr) != 0)
			//errx(EX_NOHOST, "hostname ``%s'' unknown", *av);
		return 2;
		ac--;
		av++;
		if (do_add && ac)
			ent.value = strtoul(*av, NULL, 0);
		else
			ent.value = 0;
		if (do_cmd(do_add ? IP_FW_TABLE_ADD : IP_FW_TABLE_DEL,
			   &ent, sizeof(ent)) < 0)
			//err(EX_OSERR, "setsockopt(IP_FW_TABLE_%s)",
			      //do_add ? "ADD" : "DEL");
		return 1;
	} else if (_substrcmp(*av, "flush") == 0) {
		if (do_cmd(IP_FW_TABLE_FLUSH, &ent.tbl, sizeof(ent.tbl)) < 0)
			err(EX_OSERR, "setsockopt(IP_FW_TABLE_FLUSH)");
	} else if (_substrcmp(*av, "list") == 0) {
		a = ent.tbl;
		l = sizeof(a);
		if (do_cmd(IP_FW_TABLE_GETSIZE, &a, (uintptr_t) & l) < 0)
			err(EX_OSERR, "getsockopt(IP_FW_TABLE_GETSIZE)");
		l = sizeof(*tbl) + a * sizeof(ipfw_table_entry);
		tbl = malloc(l);
		if (tbl == NULL)
			err(EX_OSERR, "malloc failed");
		tbl->tbl = ent.tbl;
		if (do_cmd(IP_FW_TABLE_LIST, tbl, (uintptr_t) & l) < 0)
			err(EX_OSERR, "getsockopt(IP_FW_TABLE_LIST)");
		for (a = 0; a < tbl->cnt; a++) {
			process_record(inet_ntoa(*(struct in_addr *)&tbl->ent[a].addr),
				       tbl->ent[a].value);
			/*
			 * printf("%s/%u %u\n", inet_ntoa(*(struct in_addr
			 * *)&tbl->ent[a].addr), tbl->ent[a].masklen,
			 * tbl->ent[a].value);
			 */
		}
		free(tbl);

	} else
		errx(EX_USAGE, "invalid table command %s", *av);
	return 0;
}
