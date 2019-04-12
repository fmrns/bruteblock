#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <err.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/param.h>
#include "pidfile.h"
#include <sysexits.h>

#include "bruteblock.h"

int		ipfw2_table_no = -1;
static int	exit_requested = 0;

static void
handle_sigs(int __unused sig)
{
	exit_requested = 1;
}

static void
usage(void)
{
	fprintf(stderr,
		"\n"
		"Usage: bruteblockd -t table [-s seconds]\n"
		"       -t          set the IPFW table number\n"
		"       -s          set the sleep time between cycles, default: 5sec\n"
		"       -p          PID file path, default: none\n"
		"       -f          run the daemon in the foreground (do not daemonize)\n"
		"       -h          print this message.\n" "\n");

	exit(1);
}

int 
delete_host(const char *host, int prefixlen, ipfw_optval_t exptime)
{
	int		rc = 0;
	char		mode      [] = IPFW_CMD_TABLE;
	char		table     [16];
	char		ipaddr    [128];	/* maxlen: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xxx */
	char		command   [] = IPFW_CMD_TABLE_DEL;
#define ARGC	4
	char	       *argv[ARGC];

	snprintf(table, sizeof(table), "%d", ipfw2_table_no);
	snprintf(ipaddr, sizeof(ipaddr), "%s/%d", host, prefixlen);

	argv[0] = mode;
	argv[1] = table;
	argv[2] = command;
	argv[3] = ipaddr;

	/* See bruteblock.h for (ipfw_optval_t) */
	if ((s_ipfw_optval_t) ((ipfw_optval_t) time(NULL) - exptime) > 0) {
		/* e.g. (s_ipfw_opt_val) ((ipfw_optval_t) 1 - (ipfw_optval_t) 0xFFFFFFFF) > 0: is true  */
		syslog(LOG_INFO, "Removing host %s from table %s", argv[3], argv[1]);
		rc = ipfw_table_handler(ARGC, argv);
	}
	return 0;
}

int
main(int ac, char *av[])
{
	int		argc;
	int		rc = 0,	ch;
	int		sleep_time = 5;	/* 5 sec default sleep time */
	int		daemonize = 1;
	const char     *pid_file = NULL;
	struct pidfh   *pfh = NULL;

	char		mode      [] = IPFW_CMD_TABLE;
	char		table     [100] = "";
	char		command   [] = IPFW_CMD_TABLE_LIST;

	char          **argv;

	if (ac <= 2) {
		usage();
		exit(1);
	}
	openlog("bruteblockd", LOG_PID | LOG_NDELAY, LOG_AUTH);
	syslog(LOG_INFO, "starting....");

	while ((ch = getopt(ac, av, "t:s:hfp:")) != -1) {
		switch (ch) {

		case 't':	/* table number */
			ipfw2_table_no = atoi(optarg);
			if (ipfw2_table_no > 127 || ipfw2_table_no < 0)
				errx(EX_USAGE, "table number can be from 0 to 127");
			break;

		case 's':	/* from */
			sleep_time = atoi(optarg);
			break;
		case 'f':
			daemonize = 0;
			break;
		case 'p':
			pid_file = optarg;
			break;
		case 'h':
		default:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	if (ipfw2_table_no == -1) {
		warnx("table number required");
		usage();
	}

	signal(SIGINT, handle_sigs);
	signal(SIGTERM, handle_sigs);
	signal(SIGPIPE, SIG_IGN);

	if (pid_file) {
		pid_t		otherpid;
		pfh = pidfile_open(pid_file, 0600, &otherpid);
		if (pfh == NULL) {
			if (errno == EEXIST) {
				errx(EXIT_FAILURE, "bruteblockd already running, pid: %d",
				     otherpid);
			}
			warn("cannot open pid file");
		}
	}

	if (daemonize) {
		if (daemon(0, 0)) {
			if (pid_file) {
				pidfile_remove(pfh);
			}
			errx(EX_OSERR, "Failed to become a daemon");
		}
	}

	if (pid_file) {
		pidfile_write(pfh);
	}
	argc = 3;
	argv = calloc(argc, sizeof(char *));
	argv[0] = mode;
	argv[1] = table;
	argv[2] = command;

	for (;;) {
		if (exit_requested) {
			break;
		}
		snprintf(table, sizeof(table), "%d", ipfw2_table_no);
		rc = ipfw_table_handler(argc, argv);
		sleep(sleep_time);
	}

	if (pid_file) {
		pidfile_remove(pfh);
	}
	free(argv);
	closelog();
	exit(EXIT_SUCCESS);
}
