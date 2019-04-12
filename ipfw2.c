/*
 * Copyright (c) 2002-2003 Luigi Rizzo
 * Copyright (c) 1996 Alex Nash, Paul Traina, Poul-Henning Kamp
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 *
 * Idea and grammar partially left from:
 * Copyright (c) 1993 Daniel Boulet
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 * NEW command line interface for IP firewall facility
 *
 * $FreeBSD$
 */
/*
 * Copyright (c) 2006 Alex Samorukov, bruteblock
 *
 * 201603325: Fumiyuki Shimizu: fumifumi@abacustech.jp
 *  Ripped from 10.2.0 r286717 to enable IPv6, and reformed.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

/* #include "ipfw2.h" bruteblock */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>	/* ctime */
#include <timeconv.h>	/* _long_to_time */
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>	/* offsetof */
#include <syslog.h>	/* bruteblock */

#include <net/ethernet.h>
#include <net/if.h>		/* only IFNAMSIZ */
#include <netinet/in.h>
#include <netinet/in_systm.h>	/* only n_short, n_long */
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_fw.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "bruteblock.h"


typedef struct {
	int test_only;		/* always false for bruteblock. */
	int do_quiet;		/* always true. Update tha ipfw table quietly.
				 * a time lag exists between expiration and removal,
				 * since the entry is created by bruteblock
				 * and is removed by bruteblockd.
				 */
	int do_value_as_ip;	/* always false for bruteblock, since it is used as timestamp */
} ipfw_opts;
ipfw_opts co = { 0, 1, 0 };

static int ipfw_socket = -1; /* bruteblock */

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#define NEED1(msg)      {if (!(*av)) errx(EX_USAGE, msg);}



static void * /* bruteblock */
safe_calloc(size_t number, size_t size)
{
	void *ret = calloc(number, size);

	if (ret == NULL)
		err(EX_OSERR, "calloc");
	return ret;
}

/*
 * conditionally runs the command.
 * Selected options or negative -> getsockopt
 */
static int /* bruteblock */
do_cmd(int optname, void *optval, uintptr_t optlen)
{
	int i;

	if (co.test_only)
		return 0;

	if (ipfw_socket == -1)
		ipfw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (ipfw_socket < 0)
		err(EX_UNAVAILABLE, "socket");

	if (optname == IP_FW_GET || optname == IP_DUMMYNET_GET ||
	    optname == IP_FW_ADD || optname == IP_FW3 ||
	    optname == IP_FW_NAT_GET_CONFIG ||
	    optname < 0 ||
	    optname == IP_FW_NAT_GET_LOG) {
		if (optname < 0)
			optname = -optname;
		i = getsockopt(ipfw_socket, IPPROTO_IP, optname, optval,
			(socklen_t *)optlen);
	} else {
		i = setsockopt(ipfw_socket, IPPROTO_IP, optname, optval, optlen);
	}
	return i;
}

/*
 * do_setcmd3 - pass ipfw control cmd to kernel
 * @optname: option name
 * @optval: pointer to option data
 * @optlen: option length
 *
 * Function encapsulates option value in IP_FW3 socket option
 * and calls setsockopt().
 * Function returns 0 on success or -1 otherwise.
 */
static int
do_setcmd3(int optname, void *optval, socklen_t optlen)
{
	socklen_t len;
	ip_fw3_opheader *op3;

	if (co.test_only)
		return (0);

	if (ipfw_socket == -1)
		ipfw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (ipfw_socket < 0)
		err(EX_UNAVAILABLE, "socket");

	len = sizeof(ip_fw3_opheader) + optlen;
	op3 = alloca(len);
	/* Zero reserved fields */
	memset(op3, 0, sizeof(ip_fw3_opheader));
	memcpy(op3 + 1, optval, optlen);
	op3->opcode = optname;

	return setsockopt(ipfw_socket, IPPROTO_IP, IP_FW3, op3, len);
}

/*
 * _substrcmp takes two strings and returns 1 if they do not match,
 * and 0 if they match exactly or the first string is a sub-string
 * of the second.  A warning is printed to stderr in the case that the
 * first string is a sub-string of the second.
 *
 * This function will be removed in the future through the usual
 * deprecation process.
 */
static int /* bruteblock */
_substrcmp(const char *str1, const char* str2)
{

	if (strncmp(str1, str2, strlen(str1)) != 0)
		return 1;

	if (strlen(str1) != strlen(str2))
		warnx("DEPRECATED: '%s' matched '%s' as a sub-string",
		    str1, str2);
	return 0;
}

static int
lookup_host (char *host, struct in_addr *ipaddr)
{
	struct hostent *he;

	if (!inet_aton(host, ipaddr)) {
		if ((he = gethostbyname(host)) == NULL)
			return(-1);
		*ipaddr = *(struct in_addr *)he->h_addr_list[0];
	}
	return(0);
}


static void table_list(uint16_t num, int need_header);
static void table_fill_xentry(char *arg, ipfw_table_xentry *xent);

/*
 * This one handles all table-related commands
 * 	ipfw table N add addr[/masklen] [value]
 * 	ipfw table N delete addr[/masklen]
 * 	ipfw table {N | all} flush
 * 	ipfw table {N | all} list
 */
int /* bruteblock */
ipfw_table_handler(int ac, char *av[])
{
	ipfw_table_xentry xent;
	int do_add;
	int is_all;
#if 0 /* bruteblock */
	uint32_t a;
	uint32_t tables_max;

	tables_max = ipfw_get_tables_max();
#endif /* bruteblock */

	memset(&xent, 0, sizeof(xent));

	ac--; av++;
	if (ac && isdigit(**av)) {
		xent.tbl = atoi(*av);
		is_all = 0;
		ac--; av++;
#if 0 /* bruteblock */
	} else if (ac && _substrcmp(*av, "all") == 0) {
		xent.tbl = 0;
		is_all = 1;
		ac--; av++;
#endif /* bruteblock */
	} else
		errx(EX_USAGE, "table number or 'all' keyword required");
#if 0 /* bruteblock */
	if (xent.tbl >= tables_max)
		errx(EX_USAGE, "The table number exceeds the maximum allowed "
			"value (%d)", tables_max - 1);
#endif /* bruteblock */
	NEED1("table needs command");
	if (is_all && _substrcmp(*av, IPFW_CMD_TABLE_LIST) != 0
		   && _substrcmp(*av, "flush") != 0)
		errx(EX_USAGE, "table number required");

	if (_substrcmp(*av, IPFW_CMD_TABLE_ADD) == 0 ||
	    _substrcmp(*av, IPFW_CMD_TABLE_DEL) == 0) {
		do_add = **av == 'a';
		ac--; av++;
		if (!ac)
			errx(EX_USAGE, "address required");

		/* bruteblock */
		if ('[' == **av && ']' == *(*av + (strlen(*av) - 1))) {
			*(*av + (strlen(*av) - 1)) = 0;
			table_fill_xentry(*av + 1, &xent);
		  
		} else {
			table_fill_xentry(*av, &xent);
		}
		if (IPFW_TABLE_CIDR != xent.type) {
			syslog(LOG_WARNING, "Unknown type: %s", *av);
			return 1;
		}

		ac--; av++;
		if (do_add && ac) {
			unsigned int tval;
			/* isdigit is a bit of a hack here.. */
			if (strchr(*av, (int)'.') == NULL && isdigit(**av))  {
				xent.value = strtoul(*av, NULL, 0);
			} else {
				if (lookup_host(*av, (struct in_addr *)&tval) == 0) {
					/* The value must be stored in host order	 *
					 * so that the values < 65k can be distinguished */
		       			xent.value = ntohl(tval);
				} else {
					/*errx(EX_NOHOST, "hostname ``%s'' unknown", *av);*/
					syslog(LOG_WARNING, "hostname ``%s'' unknown", *av);
					return 2; /* bruteblock */
				}
			}
		} else
			xent.value = 0;
		if (do_setcmd3(do_add ? IP_FW_TABLE_XADD : IP_FW_TABLE_XDEL,
		    &xent, xent.len) < 0) {
			/* If running silent, don't bomb out on these errors. */
			if (!(co.do_quiet && (errno == (do_add ? EEXIST : ESRCH)))) {
				/*err(EX_OSERR, "setsockopt(IP_FW_TABLE_%s)",
				    do_add ? "XADD" : "XDEL");*/
				syslog(LOG_WARNING,"setsockopt(IP_FW_TABLE_%s)",
				       do_add ? "XADD" : "XDEL");
				return 1; /* bruteblock */
			}
			/* In silent mode, react to a failed add by deleting */
			if (do_add) {
				do_setcmd3(IP_FW_TABLE_XDEL, &xent, xent.len);
				if (do_setcmd3(IP_FW_TABLE_XADD, &xent, xent.len) < 0) {
					/*err(EX_OSERR,
					    "setsockopt(IP_FW_TABLE_XADD)");*/
					syslog(LOG_WARNING,"setsockopt(IP_FW_TABLE_%s)",
					       do_add ? "XADD" : "XDEL");
					return 1; /* bruteblock */
				}
				return -1; /* bruteblock */
			}
		}
#if 0 /* bruteblock */
	} else if (_substrcmp(*av, "flush") == 0) {
		a = is_all ? tables_max : (uint32_t)(xent.tbl + 1);
		do {
			if (do_cmd(IP_FW_TABLE_FLUSH, &xent.tbl,
			    sizeof(xent.tbl)) < 0)
				err(EX_OSERR, "setsockopt(IP_FW_TABLE_FLUSH)");
		} while (++xent.tbl < a);
#endif /* bruteblock */
	} else if (_substrcmp(*av, IPFW_CMD_TABLE_LIST) == 0) {
#if 0 /* bruteblock */
		a = is_all ? tables_max : (uint32_t)(xent.tbl + 1);
		do {
			table_list(xent.tbl, is_all);
		} while (++xent.tbl < a);
#else
		table_list(xent.tbl, is_all);
#endif /* bruteblock */
	} else
		errx(EX_USAGE, "invalid table command %s", *av);
	return 0; /* bruteblock */
}

static void
table_fill_xentry(char *arg, ipfw_table_xentry *xent)
{
	int addrlen, mask, masklen, type;
	struct in6_addr *paddr;
	uint32_t *pkey;
	char *p;
	uint32_t key;

	mask = 0;
	type = 0;
	addrlen = 0;
	masklen = 0;

	/* 
	 * Let's try to guess type by agrument.
	 * Possible types: 
	 * 1) IPv4[/mask]
	 * 2) IPv6[/mask]
	 * 3) interface name
	 * 4) port, uid/gid or other u32 key (base 10 format)
	 * 5) hostname
	 */
	paddr = &xent->k.addr6;
	if (ishexnumber(*arg) != 0 || *arg == ':') {
		/* Remove / if exists */
		if ((p = strchr(arg, '/')) != NULL) {
			*p = '\0';
			mask = atoi(p + 1);
		}

		if (inet_pton(AF_INET, arg, paddr) == 1) {
			if (p != NULL && mask > 32) {
				/* errx(EX_DATAERR, "bad IPv4 mask width: %s",
				    p + 1); */
				syslog(LOG_WARNING, "bad IPv4 mask width: %s",
				       p + 1);
				type = IPFW_TABLE_INTERFACE;
				return;
			}

			type = IPFW_TABLE_CIDR;
			masklen = p ? mask : 32;
			addrlen = sizeof(struct in_addr);
		} else if (inet_pton(AF_INET6, arg, paddr) == 1) {
			if (IN6_IS_ADDR_V4COMPAT(paddr)) {
				/* errx(EX_DATAERR,
				    "Use IPv4 instead of v4-compatible"); */
				syslog(LOG_WARNING, "Use IPv4 instead of v4-compatible");
				type = IPFW_TABLE_INTERFACE;
				return;
			}
			if (p != NULL && mask > 128) {
				/* errx(EX_DATAERR, "bad IPv6 mask width: %s",
				    p + 1); */
				syslog(LOG_WARNING, "bad IPv6 mask width: %s",
				       p + 1);
				type = IPFW_TABLE_INTERFACE;
				return;
			}
			type = IPFW_TABLE_CIDR;
			masklen = p ? mask : 128;
			addrlen = sizeof(struct in6_addr);
		} else {
			/* Port or any other key */
			/* Skip non-base 10 entries like 'fa1' */
			key = strtol(arg, &p, 10);
			if (*p == '\0') {
				pkey = (uint32_t *)paddr;
				*pkey = htonl(key);
				type = IPFW_TABLE_CIDR;
				masklen = 32;
				addrlen = sizeof(uint32_t);
			} else if ((p != arg) && (*p == '.')) {
				/*
				 * Warn on IPv4 address strings
				 * which are "valid" for inet_aton() but not
				 * in inet_pton().
				 *
				 * Typical examples: '10.5' or '10.0.0.05'
				 */
				/* errx(EX_DATAERR,
				    "Invalid IPv4 address: %s", arg); */
				syslog(LOG_WARNING, "Invalid IPv4 address: %s", arg);
				type = IPFW_TABLE_INTERFACE;
				return;
			}
		}
	}

	if (type == 0 && strchr(arg, '.') == NULL) {
		/* Assume interface name. Copy significant data only */
		mask = MIN(strlen(arg), IF_NAMESIZE - 1);
		memcpy(xent->k.iface, arg, mask);
		/* Set mask to exact match */
		masklen = 8 * IF_NAMESIZE;
		type = IPFW_TABLE_INTERFACE;
		addrlen = IF_NAMESIZE;
	}

	if (type == 0) {
		if (lookup_host(arg, (struct in_addr *)paddr) != 0) {
			/* errx(EX_NOHOST, "hostname ``%s'' unknown", arg); */
			syslog(LOG_WARNING, "hostname ``%s'' unknown", arg);
			type = IPFW_TABLE_INTERFACE;
			return;
		}

		masklen = 32;
		type = IPFW_TABLE_CIDR;
		addrlen = sizeof(struct in_addr);
	}

	xent->type = type;
	xent->masklen = masklen;
	xent->len = offsetof(ipfw_table_xentry, k) + addrlen;
}

static void
table_list(uint16_t num, int need_header)
{
	ipfw_xtable *tbl;
	ipfw_table_xentry *xent;
	socklen_t l;
	uint32_t *a, sz, tval;
	char tbuf[128];
	struct in6_addr *addr6;
	ip_fw3_opheader *op3;

	/* Prepend value with IP_FW3 header */
	l = sizeof(ip_fw3_opheader) + sizeof(uint32_t);
	op3 = alloca(l);
	/* Zero reserved fields */
	memset(op3, 0, sizeof(ip_fw3_opheader));
	a = (uint32_t *)(op3 + 1);
	*a = num;
	op3->opcode = IP_FW_TABLE_XGETSIZE;
	if (do_cmd(IP_FW3, op3, (uintptr_t)&l) < 0)
		err(EX_OSERR, "getsockopt(IP_FW_TABLE_XGETSIZE)");

	/* If a is zero we have nothing to do, the table is empty. */
	if (*a == 0)
		return;

	l = *a;
	tbl = safe_calloc(1, l);
	tbl->opheader.opcode = IP_FW_TABLE_XLIST;
	tbl->tbl = num;
	if (do_cmd(IP_FW3, tbl, (uintptr_t)&l) < 0)
		err(EX_OSERR, "getsockopt(IP_FW_TABLE_XLIST)");
	if (tbl->cnt && need_header)
		printf("---table(%d)---\n", tbl->tbl);
	sz = tbl->size - sizeof(ipfw_xtable);
	xent = &tbl->xent[0];
	while (sz > 0) {
		switch (tbl->type) {
		case IPFW_TABLE_CIDR:
			/* IPv4 or IPv6 prefixes */
			tval = xent->value;
			addr6 = &xent->k.addr6;


			if (IN6_IS_ADDR_V4COMPAT(addr6)) {
				/* IPv4 address */
				inet_ntop(AF_INET, &addr6->s6_addr32[3], tbuf, sizeof(tbuf));
			} else {
				/* IPv6 address */
				inet_ntop(AF_INET6, addr6, tbuf, sizeof(tbuf));
			}

			if (co.do_value_as_ip) {
				tval = htonl(tval);
				printf("%s/%u %s\n", tbuf, xent->masklen,
				    inet_ntoa(*(struct in_addr *)&tval));
			} else {
#ifdef NO_DELETE_IPFWTABLELIST
				printf("%s/%u %u\n", tbuf, xent->masklen, tval);
#else
				delete_host(tbuf, xent->masklen, tval);	/* bruteblock */
#endif
			}
			break;
		case IPFW_TABLE_INTERFACE:
			/* Interface names */
			tval = xent->value;
			if (co.do_value_as_ip) {
				tval = htonl(tval);
				printf("%s %s\n", xent->k.iface,
				    inet_ntoa(*(struct in_addr *)&tval));
			} else {
				/* printf("%s %u\n", xent->k.iface, tval); bruteblock */
			}
		}

		if (sz < xent->len)
			break;
		sz -= xent->len;
		xent = (ipfw_table_xentry *)((char *)xent + xent->len);
	}

	free(tbl);
}

/* end of file */
