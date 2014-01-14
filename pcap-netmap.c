/*
 * Copyright 2014 Universita` di Pisa
 *
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * packet filter subroutines for netmap
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#if 0
struct mbuf;
struct rtentry;
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Make "pcap.h" not include "pcap/bpf.h"; we are going to include the
 * native OS version, as we need various BPF ioctls from it.
 */
// #define PCAP_DONT_INCLUDE_PCAP_BPF_H
// #include <net/bpf.h>

#include "pcap-int.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

struct pcap_netmap {
	struct nm_desc_t *d;

	int	filtering_in_kernel; /* using kernel filter */
	u_long	TotPkts;	/* can't oflow for 79 hrs on ether */
	u_long	TotAccepted;	/* count accepted by filter */
	u_long	TotDrops;	/* count of dropped packets */
	long	TotMissed;	/* missed by i/f during this run */
	long	OrigMissed;	/* missed by i/f before this run */
};

static int
pcap_stats_netmap(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_netmap *pf = p->priv;

	ps->ps_recv = pf->TotAccepted;
	ps->ps_drop = pf->TotDrops;
	ps->ps_ifdrop = pf->TotMissed - pf->OrigMissed;
	return (0);
}

static int
pcap_activate_netmap(pcap_t *p)
{
	struct pcap_netmap *pf = p->priv;
	short enmode;
	int backlog = -1;	/* request the most */

	/*
	 * Initially try a read/write open (to allow the inject
	 * method to work).  If that fails due to permission
	 * issues, fall back to read-only.  This allows a
	 * non-root user to be granted specific access to pcap
	 * capabilities via file permissions.
	 *
	 * XXX - we should have an API that has a flag that
	 * controls whether to open read-only or read-write,
	 * so that denial of permission to send (or inability
	 * to send, if sending packets isn't supported on
	 * the device in question) can be indicated at open
	 * time.
	 *
	 * XXX - we assume here that "pfopen()" does not, in fact, modify
	 * its argument, even though it takes a "char *" rather than a
	 * "const char *" as its first argument.  That appears to be
	 * the case, at least on Digital UNIX 4.0.
	 */
	pf->d = nm_open(p->opt.source, NULL, 0, 0);
	if (pf->d == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			"netmap open: cannot access %s: %s\n",
			p->opt.source, pcap_strerror(errno));
		goto bad;
	}
	p->fd = pf->d->fd;
	//if (!p->opt.immediate)
	//if (p->opt.promisc)
	/* set truncation */
	// if (p->opt.timeout != 0) {

	/*
	 * "select()" and "poll()" work on packetfilter devices.
	 */
	p->selectable_fd = p->fd;

	p->read_op = (void *)nm_dispatch;
	p->inject_op = (void *)nm_inject;
	p->setfilter_op = install_bpf_program;
	p->setdirection_op = NULL;	/* Not implemented. */
	p->set_datalink_op = NULL;	/* can't change data link type */
	p->getnonblock_op = pcap_getnonblock_fd;
	p->setnonblock_op = pcap_setnonblock_fd;
	p->stats_op = pcap_stats_netmap;
	// close ?
	return (0);
 bad:
	pcap_cleanup_live_common(p);
	return (PCAP_ERROR);
}

pcap_t *
pcap_netmap_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *p;

	fprintf(stderr, "---- %s --- trying device %s -----\n", __FUNCTION__, device);
	*is_ours = (!strncmp(device, "netmap:", 7) || !strncmp(device, "vale", 4));
	if (! *is_ours)
		return NULL;
		
	p = pcap_create_common(device, ebuf, sizeof (struct pcap_netmap));
	if (p == NULL)
		return (NULL);

	p->activate_op = pcap_activate_netmap;
	return (p);
}

int
pcap_netmap_finddevs(pcap_if_t **alldevsp, char *errbuf)
{
	fprintf(stderr, "called %s ---\n", __FUNCTION__);
        return (0);
}
