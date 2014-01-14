/*
 * Copyright 2014 Universita` di Pisa
 *
 * packet filter subroutines for netmap
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <poll.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcap-int.h"

struct pcap_netmap {
	struct nm_desc_t *d;

	u_char *dispatch_arg;
	pcap_handler cb;

	u_long	TotPkts;	/* can't oflow for 79 hrs on ether */
	u_long	TotAccepted;	/* count accepted by filter */
	u_long	TotDrops;	/* count of dropped packets */
	long	TotMissed;	/* missed by i/f during this run */
	long	OrigMissed;	/* missed by i/f before this run */
};

static int
pcap_stats_netmap(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_netmap *pn = p->priv;

	ps->ps_recv = pn->TotAccepted;
	ps->ps_drop = pn->TotDrops;
	ps->ps_ifdrop = pn->TotMissed - pn->OrigMissed;
	return 0;
}

static void
pcap_netmap_filter(u_char *arg, struct pcap_pkthdr *h, const u_char *buf)
{
	pcap_t *p = (pcap_t *)arg;
	struct pcap_netmap *pn = p->priv;

	pn->TotPkts++;
	if (bpf_filter(p->fcode.bf_insns, buf, h->len, h->caplen)) {
		pn->TotAccepted++;
		pn->cb(pn->dispatch_arg, h, buf);
	} else {
		pn->TotDrops++;
	}
}

static int
pcap_netmap_dispatch(pcap_t *p, int cnt, pcap_handler cb, u_char *user)
{
	int ret;
	struct pcap_netmap *pn = p->priv;
	struct nm_desc_t *d = pn->d;
	struct pollfd pfd;
	pfd.fd = p->fd;
	pfd.events = POLLIN;

	pn->cb = cb;
	pn->dispatch_arg = user;

	for (;;) {
		if (p->break_loop) {
                        p->break_loop = 0;
                        return PCAP_ERROR_BREAK;
                }
		ret = nm_dispatch((void *)d, cnt, (void *)pcap_netmap_filter, (void *)p);
		if (ret != 0)
			break;
		poll(&pfd, 1, 1000);
	}
	return ret;
}

static int
pcap_netmap_inject(pcap_t *p, const void *buf, size_t size)
{
	struct nm_desc_t *d = ((struct pcap_netmap *)p->priv)->d;

	return nm_inject(d, buf, size);
}

static void
pcap_netmap_close(pcap_t *p)
{
	struct nm_desc_t *d = ((struct pcap_netmap *)p->priv)->d;

	nm_close(d);
}

static int
pcap_activate_netmap(pcap_t *p)
{
	struct pcap_netmap *pn = p->priv;
	struct nm_desc_t *d;

	d = nm_open(p->opt.source, NULL, 0, 0);
	if (d == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			"netmap open: cannot access %s: %s\n",
			p->opt.source, pcap_strerror(errno));
		goto bad;
	}
	fprintf(stderr, "%s device %s priv %p fd %d\n",
		__FUNCTION__, p->opt.source, d, d->fd);
	pn->d = d;
	p->fd = d->fd;
	//if (!p->opt.immediate)
	//if (p->opt.promisc)
	/* set truncation */
	// if (p->opt.timeout != 0) {
	p->linktype = DLT_EN10MB;

	p->selectable_fd = p->fd;

	p->read_op = pcap_netmap_dispatch;
	p->inject_op = pcap_netmap_inject,
	p->setfilter_op = install_bpf_program;
	p->setdirection_op = NULL;	/* Not implemented. */
	p->set_datalink_op = NULL;	/* can't change data link type */
	p->getnonblock_op = pcap_getnonblock_fd;
	p->setnonblock_op = pcap_setnonblock_fd;
	p->stats_op = pcap_stats_netmap;
	p->cleanup_op = pcap_netmap_close;
	return (0);
 bad:
	pcap_cleanup_live_common(p);
	return (PCAP_ERROR);
}

pcap_t *
pcap_netmap_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *p;

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
pcap_netmap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
	// fprintf(stderr, "called %s ---\n", __FUNCTION__);
        return (0);
}
