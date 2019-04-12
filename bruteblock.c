#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <sysexits.h>
#include <stdlib.h>
#include <err.h>
#include <pcre.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "iniparse/iniparser.h"
#include "bruteblock.h"

#define MAXHOSTS 5000
#define BUFFER_SIZE 30000
#define OVECCOUNT 30		/* should be a multiple of 3 */

#define IN6_IS_ADDR_6TO4(a)	(((uint16_t *)(a))[0] == ntohs(0x2002))
#define IN4_IN6_6TO4(a)		((struct in_addr *)((uint16_t *)(a) + 1))
#define IN4_IN6_MAPPED(a)	((struct in_addr *)((uint16_t *)(a) + 6))

typedef struct {
	int		count;
	time_t		access_time;
	char		ipaddr[300];
}		hosts_table_ent;

hosts_table_ent	hosts_table[MAXHOSTS];

int		max_count = -1;
int		within_time = -1;
int		ipfw2_table_no = -1;
int		reset_ip = -1;
int		ip4prefixlen;
int		ip6prefixlen;
int		ip4also_inserts_6to4 = 0;



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
upsert_host(const char *nrmaddr)
{
	char		mode      [] = IPFW_CMD_TABLE;
	char		command   [] = IPFW_CMD_TABLE_ADD;
	char		table     [16] = "";
	char		utime     [200] = "";
#define	ARGC	5
	char	       *argv[ARGC];
	char		buf[sizeof(hosts_table->ipaddr)];
	int		i;
	time_t		curtime = time(NULL);
	int		insert = -1;
	int		update = -1;

	for (i = 0; i < MAXHOSTS; i++) {
		/* cleanup expired hosts */
		if (0 < hosts_table[i].count && hosts_table[i].access_time + within_time - curtime < 0) {
			hosts_table[i].count = 0;
		}
		if (hosts_table[i].count < 1) {
			if (0 > insert) {
				insert = i;
			}
			continue;
		}
		if (strcmp(nrmaddr, hosts_table[i].ipaddr) == 0) {
			update = i;
			break;
		}
	}
	if (0 > update) {
		if (0 > insert) {
			syslog(LOG_ERR, "Internal table is full.");
			return 99; /* error */
		}
		update = insert;
		hosts_table[insert].count = 0;
		hosts_table[insert].access_time = curtime;
		strlcpy(hosts_table[insert].ipaddr, nrmaddr, sizeof(hosts_table->ipaddr));
	}
	if (++hosts_table[update].count < max_count) {
		return -99; /* NOOP */
	}
	hosts_table[update].count = 0;

	snprintf(table, sizeof(table), "%d", ipfw2_table_no);
	snprintf(utime, sizeof(utime), FMT_IPFW_OPTVAL, (ipfw_optval_t) (curtime + reset_ip));
	strlcpy(buf, hosts_table[update].ipaddr, sizeof(buf));	/* *** ipfw_table_handler changes argv[3] *** */
	argv[0] = mode;
	argv[1] = table;
	argv[2] = command;
	argv[3] = buf;
	argv[4] = utime;

	return ipfw_table_handler(ARGC, argv); /* -1: replaced, 0: inserted, 1,...: error */
}

static void
applymask(void *addr, size_t addrsize, int cidrlen) {
	int i;
	if (8 * addrsize <= cidrlen) {
		return;
	}

	unsigned char *a = (unsigned char *) addr;
	for(i = 0; i < addrsize; ++i, ++a) {
		if (8 <= cidrlen) {
			cidrlen -= 8;
		} else {
			unsigned char m = 0;
			for (; 0 < cidrlen; --cidrlen) {
				m >>= 1;
				m |= 0x80;
			}
			*a &= m;
		}
	}
}

static void
normip6addr(char *dst, size_t dstsize, struct in6_addr *ip6addr, int prefixlen) {
	char	buf[128];	/* maxlen: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx */
	applymask(ip6addr, sizeof (*ip6addr), prefixlen);
	inet_ntop(AF_INET6, ip6addr, buf, sizeof(buf));
	snprintf(dst, dstsize, "%s/%d", buf, prefixlen);
}

static void
normip4addr(char *dst, size_t dstsize, struct in_addr *ip4addr) {
	char	buf[64];	/* maxlen: xxx.xxx.xxx.xxx/xxx */
	applymask(ip4addr, sizeof (*ip4addr), ip4prefixlen);
	inet_ntop(AF_INET, ip4addr, buf, sizeof(buf));
	snprintf(dst, dstsize, "%s/%d", buf, ip4prefixlen);
}

#define MAX_NORM_ADDR	2
static void
normaddr(char dst[MAX_NORM_ADDR][sizeof(hosts_table->ipaddr)], const char *str) {
	union {
		struct in_addr	ip4addr;
		struct in6_addr	ip6addr;
		uint16_t	part[8];
	} ipaddr;
	char buf[sizeof(hosts_table->ipaddr)];
	int i;
	int s;
	int e;

	for(i = 0; i < MAX_NORM_ADDR; ++i) {
		*dst[i] = 0;
	}

	/* remove parens */
	for(s = 0, e = strlen(str)
	    ; s + 1 < e
	      && (   ('['  == str[s] && ']'  == str[e - 1])
		  || ('('  == str[s] && ')'  == str[e - 1])
		  || ('"'  == str[s] && '"'  == str[e - 1])
		  || ('\'' == str[s] && '\'' == str[e - 1])
		  || ('<'  == str[s] && '>'  == str[e - 1]))
	    ; ++s, --e) ;
	if (s >= e) {
		return;
	}
	if (0 < s) {
		strlcpy(buf, str + s, sizeof (buf));
		if (e - s < strlen(buf)) {
			buf[e - s] = 0;
		}
	} else {
		strlcpy(buf, str, sizeof (buf));
	}

	if (NULL != strchr(buf, ':') && 1 == inet_pton(AF_INET6, buf, &ipaddr.ip6addr)) {
		if (IN6_IS_ADDR_6TO4(&ipaddr.ip6addr)) {
			normip6addr(dst[0], sizeof(*dst), &ipaddr.ip6addr, 16 + ip4prefixlen);
			normip4addr(dst[1], sizeof(*dst), IN4_IN6_6TO4(&ipaddr.ip6addr));
		} else if (IN6_IS_ADDR_V4MAPPED(&ipaddr.ip6addr)) {
			normip6addr(dst[0], sizeof(*dst), &ipaddr.ip6addr, (32 * 3) + ip4prefixlen);
			normip4addr(dst[1], sizeof(*dst), IN4_IN6_MAPPED(&ipaddr.ip6addr));
		} else if (IN6_IS_ADDR_V4COMPAT(&ipaddr.ip6addr)) {
			normip4addr(dst[0], sizeof(*dst), IN4_IN6_MAPPED(&ipaddr.ip6addr));
		} else {
			normip6addr(dst[0], sizeof(*dst), &ipaddr.ip6addr, ip6prefixlen);
		}
	} else if (NULL != strchr(buf, '.') && 1 == inet_aton(buf, &ipaddr.ip4addr)) {
		normip4addr(dst[0], sizeof(*dst), &ipaddr.ip4addr);
		if (ip4also_inserts_6to4) {
			snprintf(buf, sizeof(buf), "2002:%x:%x::", htons(ipaddr.part[0]), htons(ipaddr.part[1]));
			if (1 == inet_pton(AF_INET6, buf, &ipaddr.ip6addr)) {
				normip6addr(dst[1], sizeof(*dst), &ipaddr.ip6addr, 16 + ip4prefixlen);
			}
		}
	} else {
		size_t i;
		for(i = 0; i + 1 < sizeof(*dst) && buf[i]; ++i) {
			dst[0][i] = tolower(buf[i]);
		}
		dst[0][i] = 0;
	}
}

static int
upsert_hosts(const char *host, const char *configfile, const char *re_name) {
	char	nrmaddr[MAX_NORM_ADDR][sizeof(hosts_table->ipaddr)];
	int	i;
	int	first = -1;
	int	rc = 0;
	char	buf[256];

	if (sizeof(*nrmaddr) - 1 < strlen(host)) {
		syslog(LOG_ERR, "Too long string: %s ([%s]%s)", host, configfile, re_name);
		return 0;
	}
	normaddr(nrmaddr, host);
	for(i = 0; *nrmaddr[i] && i < MAX_NORM_ADDR; ++i) {
		int h = upsert_host(nrmaddr[i]);
		if (0 < h) {
			syslog(LOG_ERR, "Adding %s to the ipfw table %d failed, rc=%d ([%s]%-7s:%s)",
			       nrmaddr[i], ipfw2_table_no, rc, configfile, re_name, host);
		  	*nrmaddr[i] = 0;
		} else if (0 > h) {
		  	*nrmaddr[i] = 0;
		} else {
			++rc;
			if (0 > first) {
				first = i;
			}
		}
	}
	if (0 <= first) {
		*buf = 0;
		for(i = 1 + first; i < MAX_NORM_ADDR; ++i) {
			if (*nrmaddr[i]) {
				strlcat (buf, ","       , sizeof (buf));
				strlcat (buf, nrmaddr[i], sizeof (buf));
			}
		}
		syslog(LOG_INFO, "Added:%18s, ipfw table:%d ([%s]%-7s:%s)%s",
		       nrmaddr[first], ipfw2_table_no, configfile, re_name, host, buf);
	}
	return rc;
}

#if 0
static void
print_table()
{
	int		i;
	for (i = 0; i < MAXHOSTS; i++) {
		/* skip empty sets */
		if (hosts_table[i].count) {
			printf("table: ip=%s,count=%d,time=%lld(" FMT_IPFW_OPTVAL ")\n",
			hosts_table[i].ipaddr, hosts_table[i].count,
			(long long) hosts_table[i].access_time,
			(ipfw_optval_t) hosts_table[i].access_time);
		}
	}
}
#endif

int
main(int ac, char *av[])
{
	char		hostaddr  [255];
	bzero(hosts_table, sizeof(hosts_table));
	int		ch        , done = 0, rc,i,k,matches;
	FILE           *infile = stdin;
#define MAX_PCRE	11 /* up to 1+10 regular expressions can be used */
	pcre           *re[MAX_PCRE];
	char	       *re_name[MAX_PCRE];
	int		re_count =  0;
	const char     *error;
	int		erroffset;
	int		ovector    [OVECCOUNT];
	char           *regexp;
	char	       *buffer;
	dictionary     *ini;
	char		config_path[PATH_MAX];
	char	       *config_base = config_path;

	buffer = (char *)malloc(BUFFER_SIZE);
	if (ac < 2) {
		usage();
	}
	while ((ch = getopt(ac, av, "f:h")) != -1) {
		switch (ch) {

			case 'f':	/* config file */
				strlcpy(config_path, optarg, sizeof(config_path));
				config_base = strrchr(config_path, '/');
				if (NULL != config_base) {
					++config_base;
				} else {
					config_base = config_path;
				}
				break;
			case 'h':
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


	max_count = iniparser_getint(ini, ":max_count", -1);
	if (max_count < 0) {
		syslog(LOG_ALERT, "Configuration error - 'max_count' key not found in \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	if (max_count < 1) {
		syslog(LOG_ALERT, "Configuration error - invalid 'max_count' in \"%s\"",
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
	ip4prefixlen = iniparser_getint(ini, ":ip4prefixlen", 32);
	if (ip4prefixlen < 0) {
		syslog(LOG_ALERT, "Configuration error - 'ip4prefixlen' must be positive number. \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	if (ip4prefixlen > 32) {
		syslog(LOG_ALERT, "Configuration error - 'ip4prefixlen' must be less than or equal to 32. \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	ip6prefixlen = iniparser_getint(ini, ":ip6prefixlen", 128);
	if (ip6prefixlen < 0) {
		syslog(LOG_ALERT, "Configuration error - 'ip6prefixlen' must be positive number. \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	if (ip6prefixlen > 128) {
		syslog(LOG_ALERT, "Configuration error - 'ip6prefixlen' must be less than or equal to 128. \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	if (NULL != (regexp = iniparser_getstr(ini, ":ip4inserts6to4"))
	    && (0 ==strcasecmp("yes", regexp) || 0 ==strcasecmp("on", regexp) || 0 == strcmp("1", regexp))) {
		ip4also_inserts_6to4 = 1;
	}



	for(i=0;i<MAX_PCRE;i++){
		if (0 == i) {
			strlcpy(buffer, ":regexp", BUFFER_SIZE);
		} else {
			snprintf(buffer, BUFFER_SIZE, ":regexp%d", i - 1);
		}
		regexp = iniparser_getstr(ini, buffer);
		if (regexp) {
			/* syslog(LOG_DEBUG, "Compiling [%s](%s%s)", regexp, config_path, buffer); */
			re[re_count] = pcre_compile(
			regexp,	/* the pattern */
			PCRE_CASELESS,	/* case insensitive match */
			&error,	/* for error message */
			&erroffset,	/* for error offset */
			NULL);/* use default character tables */
			if (re[re_count] == NULL) {
				syslog(LOG_ERR, "PCRE [%s%s] compilation failed at offset %d: %s", config_path, buffer, erroffset, error);
				exit(EX_SOFTWARE);
			}
			re_name[re_count] = strdup(buffer);
			re_count++;
		}
	}
	if (1 > re_count) {
		syslog(LOG_ALERT, "Configuration error - 'regexp' key not found in \"%s\"",
		config_path);
		exit(EX_CONFIG);
	}
	iniparser_freedict(ini);/* Release memory used for the configuration */



	while (!done) { /* main loop */
		if (fgets(buffer, BUFFER_SIZE, infile) == NULL)
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

			matches = 0;
			for (i = 1; i < rc; i++)
			{
				char *substring_start = buffer + ovector[2*i];
				int substring_length = ovector[2*i+1] - ovector[2*i];
				if(substring_length){ /* skip "unset" patterns */
					snprintf(hostaddr, sizeof(hostaddr), "%.*s",
					substring_length, substring_start);
					matches++;
				}
			}
			if (matches == 1){ /* we have ip address to add */
				upsert_hosts(hostaddr, config_base, re_name[k]);
				break;
			} else { /* error in regexp */
				syslog(LOG_ERR, "error: regexp matched %d times!", matches);
				break;
			}
		}

	}
	free(buffer);
	for(i=0;i<re_count;i++)	{
		free(re[i]); /* release re memory */
		free(re_name[i]);
	}
	return EX_OK;
}
