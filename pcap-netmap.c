/*
 * Copyright 2014 Universita` di Pisa
 *
 * packet filter subroutines for netmap
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <poll.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "pcap-int.h"

#if defined (linux)
/* on FreeBSD we use IFF_PPROMISC which is in flagshigh.
 * remap to IFF_PROMISC on linux
 */
#define IFF_PPROMISC	IFF_PROMISC
#define ifr_flagshigh	ifr_flags
#endif /* linux */

struct pcap_netmap {
	struct nm_desc_t *d;	/* pointer returned by nm_open() */
	pcap_handler cb;	/* callback and argument */
	u_char *cb_arg;
	int must_clear_promisc;	/* flag */
	uint64_t rx_pkts;	/* count accepted by filter */
};

static int
pcap_stats_netmap(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_netmap *pn = p->priv;

	ps->ps_recv = pn->rx_pkts;
	ps->ps_drop = 0;
	ps->ps_ifdrop = 0;
	return 0;
}

static void
pcap_netmap_filter(u_char *arg, struct pcap_pkthdr *h, const u_char *buf)
{
	pcap_t *p = (pcap_t *)arg;
	struct pcap_netmap *pn = p->priv;

	++pn->rx_pkts;
	if (bpf_filter(p->fcode.bf_insns, buf, h->len, h->caplen)) {
		pn->cb(pn->cb_arg, h, buf);
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
	pn->cb_arg = user;

	for (;;) {
		if (p->break_loop) {
                        p->break_loop = 0;
                        return PCAP_ERROR_BREAK;
                }
		/* nm_dispatch won't run forever */
		ret = nm_dispatch((void *)d, cnt, (void *)pcap_netmap_filter, (void *)p);
		if (ret != 0)
			break;
		poll(&pfd, 1, p->opt.timeout);
	}
	return ret;
}

/* XXX need to check the NIOCTXSYNC/poll */
static int
pcap_netmap_inject(pcap_t *p, const void *buf, size_t size)
{
	struct nm_desc_t *d = ((struct pcap_netmap *)p->priv)->d;

	return nm_inject(d, buf, size);
}

static int
pcap_netmap_ioctl(pcap_t *p, u_long what, uint32_t *if_flags)
{
	struct pcap_netmap *pn = p->priv;
	struct nm_desc_t *d = pn->d;
	struct ifreq ifr;
	int error, fd;

#if defined( __FreeBSD__ ) || defined (__APPLE__)
	fd = me->fd;
#endif

#ifdef linux
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Error: cannot get device control socket.\n");
		return -1;
	}
#endif /* linux */
	bzero(&ifr, sizeof(ifr));
        strncpy(ifr.ifr_name, d->req.nr_name, sizeof(ifr.ifr_name));
        switch (what) {
	case SIOCSIFFLAGS:
		ifr.ifr_flags = *if_flags;
		ifr.ifr_flagshigh = *if_flags >> 16;
		break;
	}
	error = ioctl(fd, what, &ifr);
	fprintf(stderr, "%s %s ioctl 0x%lx returns %d\n", __FUNCTION__,
		d->req.nr_name, what, error);
	if (error)
		return -1;
	switch (what) {
	case SIOCGIFFLAGS:
		*if_flags = ifr.ifr_flags | (ifr.ifr_flagshigh << 16);
	}
	return 0;
}

static void
pcap_netmap_close(pcap_t *p)
{
	struct pcap_netmap *pn = p->priv;
	struct nm_desc_t *d = pn->d;

	if (pn->must_clear_promisc) {
		uint32_t if_flags = 0;
		pcap_netmap_ioctl(p, SIOCGIFFLAGS, &if_flags); /* fetch flags */
		if (if_flags & IFF_PPROMISC) {
			if_flags &= ~IFF_PPROMISC;
			pcap_netmap_ioctl(p, SIOCSIFFLAGS, &if_flags);
		}
	}
	nm_close(d);
}

static int
pcap_activate_netmap(pcap_t *p)
{
	struct pcap_netmap *pn = p->priv;
	struct nm_desc_t *d;

	/* maybe trim queue after the '-' */
	d = nm_open(p->opt.source, NULL, 0, 0);
	if (d == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			"netmap open: cannot access %s: %s\n",
			p->opt.source, pcap_strerror(errno));
		goto bad;
	}
	fprintf(stderr, "%s device %s priv %p fd %d ports %d..%d\n",
		__FUNCTION__, p->opt.source, d, d->fd, d->first_rx_ring, d->last_rx_ring);
	pn->d = d;
	p->fd = d->fd;
	// fprintf(stderr, "timeout %d imm %d promisc %d\n",
	//	p->opt.timeout, p->opt.immediate, p->opt.promisc);
	if (!(d->req.nr_ringid & NETMAP_SW_RING) && p->opt.promisc) {
		uint32_t if_flags = 0;
		pcap_netmap_ioctl(p, SIOCGIFFLAGS, &if_flags); /* fetch flags */
		if (!(if_flags & IFF_PPROMISC)) {
			pn->must_clear_promisc = 1;
			if_flags |= IFF_PPROMISC;
			pcap_netmap_ioctl(p, SIOCSIFFLAGS, &if_flags);
		}
	}
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
