This repository contains a [netmap](http://info.iet.unipi.it/~luigi/netmap/)-enabled version of libpcap from https://github.com/the-tcpdump-group/libpcap.git . With this, basically any pcap application can read/write traffic at 10+ Mpps rather than the 1-2 Mpps achievable with bpf or similar interfaces. **NOTE** you will only see the speedup if the application is able to process data at that speed. Some are (e.g. tcpdump doing bpf filtering), but this is not always the case.

This version of the code has zerocopy reads and soon we will introduce support for zerocopy writes.

The **netmap** packet I/O framework is described at http://info.iet.unipi.it/~luigi/netmap/.

Other related repositories of interest (in all cases we track the original repositories and will try to upstream our changes):

  * https://code.google.com/p/netmap/ the latest version of netmap source code (kernel module and examples) for FreeBSD and Linux. Note, FreeBSD distribution include netmap natively.
  * https://code.google.com/p/netmap-click a netmap-enabled version of the Click Modular Router from git://github.com/kohler/click.git . This version matches the current version of netmap, supporting all features (including netmap pipes)
  * https://code.google.com/p/netmap-ipfw a netmap-enabled, userspace version of the ipfw firewall and dummynet network emulator. This version reaches 7-10 Mpps for filtering and over 2.5 Mpps for emulation.