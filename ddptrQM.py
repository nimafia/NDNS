#!/usr/bin/env python2
#
# Copyright 2017 Nima Azizzadeh <https://github.com/nimafia/ddprtrQM/>
#
# DNS delegation path traceroute tools with supporting QNAME minimization
#
# Thanks to Philipp Winter <phw@nymity.ch> for starting this up.
# ddprtrQM is developed version of ddptr >> https://github.com/NullHypothesis/ddptr/
#
#
# You should have received a copy of the GNU General Public License
# along with exitmap.  If not, see <http://www.gnu.org/licenses/>.

"""
Runs UDP traceroutes to servers in DNS delegation path for a given FQDN.
"""

import os
import re
import sys
import logging as log
import argparse
import subprocess
import collections

import pyasn
import scapy.all as scapy

DIG_OUTPUT_MATCH = r"^;; Received \d+ bytes from ([^\(]+)\([^ ]*\) in \d+ ms$"

IPASN_URL = "https://github.com/hadiasghari/pyasn"

Host = collections.namedtuple("Host", "addr port")


class Stats(object):
    def __init__(self):
        self.dns_asns = []
        self.dns_asns_qmin = []
        self.web_asns = []

stats = Stats()


def substring_after(s, delim):
    return s.partition(delim)[2]

def parse_arguments():
    """
    Parse command line arguments.
    """

    desc = "DNS delegation path traceroute"
    parser = argparse.ArgumentParser(description=desc)

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("--fqdn-file", type=str, default=None,
                       help="A file containing fully qualified domain names, "
                            "one per line.")

    group.add_argument("--fqdn", type=str, default=None,
                       help="A fully qualified domain name.")

    parser.add_argument("asn_db", metavar="ASN_DB", type=str,
                        help="The ASN database that is needed to map IP "
                             "addresses to autonomous system numbers.  For "
                             "more details, see: <%s>" % IPASN_URL)

    parser.add_argument("-g", "--graph-output", type=str, default=None,
                        help="Name template of the SVG files that visualise "
                             "the traceroutes.  The name will be prefixed "
                             "with `dns-servers_' and `web-server_'.")

    parser.add_argument("-v", "--verbosity", type=str, default="info",
                        help="Minimum verbosity level for logging.  "
                             "Available, in ascending order: debug, info, "
                             "warning, error, critical).  The default is "
                             "`info'.")

    parser.add_argument("-d", "--dns-server", type=str, default="8.8.8.8",
                        help="The DNS server that is used do determine the "
                             "delegation path.  The default is 8.8.8.8.")

    return parser.parse_args()


def load_fqdns(file_name):
    """
    Load FQDNs from the given file, one per line.
    """

    fqdns = []

    try:
        with open(file_name, "r") as fqdn_file:
            for line in fqdn_file:
                fqdns.append(line.strip())
    except IOError as err:
        log.critical("Couldn't open file %s: %s" % (file_name, err))
        sys.exit(1)

    log.info("Loaded %d FQDNs from file: %s" % (len(fqdns), file_name))

    return fqdns


def asns_in_traceroute(traceroute, asndb):
    """
    Extract ASNs of hops in traceroute and return them as list.
    """

    asns = []

    for sent, recvd in traceroute:

        # Is the response an ICMP TTL Exceeded packet?

        if recvd.haslayer(scapy.ICMP) and recvd.payload.type == 11:
            asn, _ = asndb.lookup(recvd.src)
            if asn is not None:
                asns.append(asn)

    return asns


def asn_comparison(dns_asns, dns_asns_qmin, web_asns):
    """
    Analyse overlap between traversed DNS and web ASNs.
    """

    if len(dns_asns) == 0 or len(web_asns) == 0 or len(dns_asns_qmin) == 0 :
        log.warning("Invalid data length (dns=%d, dns-q=%d, web=%d)" % (len(dns_asns),
                                                              len(dns_asns_qmin),
                                                              len(web_asns)))
        return

    dns_asns = set([str(x) for x in dns_asns])
    dns_asns_qmin = set([str(x) for x in dns_asns_qmin])
    web_asns = set([str(x) for x in web_asns])

    log.info("%d ASNs in DNS hops: %s" % (len(dns_asns), ",".join(dns_asns)))
    log.info("%d (if qmin enabed)ASNs in DNS hops: %s" % (len(dns_asns_qmin), ",".join(dns_asns_qmin)))
    log.info("%d ASNs in web hops: %s" % (len(web_asns), ",".join(web_asns)))

    intersection = web_asns.intersection(dns_asns)
    log.info("%d intersections between web and DNS ASNs: %s" %
             (len(intersection), ",".join(intersection)))
	
    intersection_qmin = web_asns.intersection(dns_asns_qmin)
    log.info("%d (If QMIN Enabled)intersections between web and DNS ASNs: %s" %
             (len(intersection_qmin), ",".join(intersection_qmin)))

    dns_only = dns_asns.difference(web_asns)
    log.info("%d ASNs in DNS but not in web ASNs: %s" %
             (len(dns_only), ",".join(dns_only)))
			 
    dns_qmin_only = dns_asns_qmin.difference(web_asns)
    log.info("%d ASNs in DNS but not in web ASNs (With QNAME Minimization): %s" %
             (len(dns_qmin_only), ",".join(dns_qmin_only)))

    web_only = web_asns.difference(dns_asns)
    log.info("%d ASNs in web but not in DNS ASNs: %s" %
             (len(web_only), ",".join(web_only)))
			 
    web_only_ifqmin = web_asns.difference(dns_asns_qmin)
    log.info("%d ASNs in web but not in DNS ASNs (IF QMIN Enabled): %s" %
             (len(web_only_ifqmin), ",".join(web_only_ifqmin)))

    log.info("dns=(%d)%s, dns-q=(%d)%s, web=(%d)%s || only-dns=(%d)%s, only-web=(%d)%s || If QNAME Minimization Enabled ==> only-dns-q=(%d)%s, only-web-q=(%d)%s" %
             (len(dns_asns), "|".join(dns_asns),
			  len(dns_asns_qmin), "|".join(dns_asns_qmin),
              len(web_asns), "|".join(web_asns),
              len(dns_only), "|".join(dns_only),
              len(web_only), "|".join(web_only),
			  len(dns_qmin_only), "|".join(dns_qmin_only),
			  len(web_only_ifqmin), "|".join(web_only_ifqmin)))

    log.info("Exposure-nq (Without QMIN) is %.3f" % (float(len(dns_only)) /
                                   len(dns_asns.union(web_asns))))
								   
    log.info("Exposure-q (With QNAME Minimization) is %.3f" % (float(len(dns_qmin_only)) /
                                   len(dns_asns_qmin.union(web_asns))))


def traceroute_dns_servers(hosts, fqdn):
    """
    Run UDP traceroutes to the given DNS servers, using FQDN in DNS requests.
    """

    log.info("Running UDP traceroutes to %d servers." % len(hosts))

    addrs = [host.addr for host in hosts]
    udp_datagram = scapy.UDP(sport=scapy.RandShort())
    dns_msg = scapy.DNS(qd=scapy.DNSQR(qname=fqdn))

    return scapy.traceroute(addrs, l4=udp_datagram/dns_msg, verbose=0)


def traceroute_web_server(fqdn):
    """
    Run TCP traceroute to FQDN, using port 80.
    """

    log.info("Running TCP traceroute to port 80 of: %s" % fqdn)

    return scapy.traceroute(fqdn, dport=80, verbose=0)


def extract_servers(dig_output, dns_server):
    """
    Extract and return DNS server IP addresses from dig's trace output.
    """

    log.info("Extracting DNS servers from dig's output.")

    hosts = []

    lines = dig_output.split("\n")
    for line in lines:
        match = re.search(DIG_OUTPUT_MATCH, line)
        if match is None:
            continue

        log.debug("Match found: %s" % match.group(1))
        host_tuple = match.group(1).split("#")
        hosts.append(Host(*host_tuple))

    # Remove system DNS as it's just there to help.

    system_dns = Host(dns_server, "53")
    log.debug("Removing system DNS %s from server list." % str(system_dns))
    try:
        hosts.remove(system_dns)
    except ValueError as err:
        log.warning("Couldn't remove system DNS %s from list: %s" %
                    (system_dns, err))

    return hosts
	
def extract_servers_qmin(dig_output, dns_server, fqdn):
    """
    Extract and return DNS server IP addresses from dig's trace output.
    """

    log.info("Extracting DNS servers that see the full QNAME(If we use QNAME Minimization) from dig's output.")

    hosts1 = []

    lines1 = substring_after(dig_output, "global options")
    lines1 = substring_after(lines1, fqdn)
    lines1 = lines1.decode("utf-8")
    lines1 = lines1.split("\n")

    for line in lines1:
        match = re.search(DIG_OUTPUT_MATCH, line)
        if match is None:
            continue

        log.debug("Match found: %s" % match.group(1))
        host1_tuple = match.group(1).split("#")
        hosts1.append(Host(*host1_tuple))

    return hosts1


def trace_fqdn(fqdn, dns_server):
    """
    Let dig determine the DNS delegation path for a given FQDN.
    """

    log.info("Tracing delegation path for FQDN %s using %s." %
             (fqdn, dns_server))
    output = ""

    cmd = ["dig", "@" + dns_server, "+trace", fqdn]
    try:
        output = subprocess.check_output(cmd)
    except OSError as err:
        if err.errno == os.errno.ENOENT:
            log.critical("Command `dig' not found.  Install `dnsutils'?")
            sys.exit(2)
        log.critical("Error while running `dig': %s: " % err)
        sys.exit(3)
    except Exception as err:
        log.critical("Unknown error while running `dig': %s: " % err)

    return output


def determine_stats():
    """
    Determine and log relevant statistics.
    """

    log.info("Total traversed DNS ASes: %d, DNS ASes(If QMIN Enabled): %d, web ASes: %d (%.2f%%) (%.2f%%)" %
             (len(stats.dns_asns),
			  len(stats.dns_asns_qmin),
              len(stats.web_asns),
              float(len(stats.web_asns)) / len(stats.dns_asns) * 100,
			  float(len(stats.web_asns)) / len(stats.dns_asns_qmin) * 100))

    # Turn ASN lists into sets, to remove duplicates.

    dns_asns = set(stats.dns_asns)
    dns_asns_qmin = set(stats.dns_asns_qmin)
    web_asns = set(stats.web_asns)

    log.info("Unique DNS ASNs: %s" % ",".join([str(x) for x in dns_asns]))
    log.info("(If QMIN Enabled)Unique DNS ASNs: %s" % ",".join([str(x) for x in dns_asns_qmin]))
    log.info("Unique web ASNs: %s" % ",".join([str(x) for x in web_asns]))
    log.info("Total unique traversed DNS ASes: %d, Total unique traversed DNS ASes(If QMIN Enabled): %d total unique traversed "
             "web ASes: %d (%.2f%%) total unique traversed web ASes(If QMIN Enabled): %d (%.2f%%)"  %
             (len(dns_asns), len(web_asns),
			  len(dns_asns_qmin), len(web_asns),
              float(len(web_asns)) / len(dns_asns) * 100,
			  float(len(web_asns)) / len(dns_asns_qmin) * 100))

    dns_only = dns_asns.difference(web_asns)
    dns_qmin_only = dns_asns_qmin.difference(web_asns)
    web_only = web_asns.difference(dns_asns)
    web_only_ifqmin = web_asns.difference(dns_asns_qmin)
    web_pct = float(len(web_only)) / len(dns_only) * 100
    web_pct_ifqmin = float(len(web_only_ifqmin)) / len(dns_qmin_only) * 100

    log.info("Unique ASes traversed only for DNS: %d, unique ASes only "
             "traversed for web: %d (%.2f%%), || If QMIN Enabled => Unique ASes traversed only for DNS: %d, unique ASes only"
             "traversed for web: %d (%.2f%%)" %
             (len(dns_only), len(web_only), web_pct, len(dns_qmin_only), len(web_only_ifqmin), web_pct_ifqmin))


def main():
    """
    Entry point.
    """

    asndb = None
    args = parse_arguments()
    log.basicConfig(level=log.getLevelName(args.verbosity.upper()),
                    format="%(asctime)s [%(levelname)s]: %(message)s")

    log.debug("Set verbosity level to: %s" % args.verbosity)

    if os.geteuid() != 0:
        log.critical("We need root privileges to run traceroutes.")
        return 1

    try:
        asndb = pyasn.pyasn(args.asn_db)
    except Exception as err:
        log.critical("Couldn't load ASN DB file '%s': %s" % (args.asn_db, err))
        sys.exit(1)

    if args.fqdn_file:
        fqdns = load_fqdns(args.fqdn_file)
    else:
        fqdns = [args.fqdn]

    for i, fqdn in enumerate(fqdns):

        log.info("Now handling FQDN %d of %d: %s" % (i+1, len(fqdns), fqdn))

        output_bytes = trace_fqdn(fqdn, args.dns_server)
        output = output_bytes.decode("utf-8")
        log.debug("dig output: %s" % output)

        servers = extract_servers(output, args.dns_server)
        log.info("DNS servers in dig trace: %s" %
                 ", ".join([h.addr for h in servers]))
				 
        servers_qmin = extract_servers_qmin(output, args.dns_server, fqdn)
        log.info("DNS servers that can see full QNAME in dig trace(If QMIN Enabled): %s" %
                 ", ".join([h.addr for h in servers_qmin]))

        try:
            dns_trs, _ = traceroute_dns_servers(servers, fqdn)
        except Exception as err:
            log.warning("Couldn't run traceroute: %s" % err)
            continue
        if args.graph_output is not None:
            file_name = "dns-servers_%s" % args.graph_output
            dns_trs.graph(target="> %s" % file_name)
            log.info("Wrote DNS servers traceroute graph to: %s" % file_name)
			
        try:
            dns_trs_qmin, _ = traceroute_dns_servers(servers_qmin, fqdn)
        except Exception as err:
            log.warning("For QMIN - Couldn't run traceroute : %s" % err)
            continue
        if args.graph_output is not None:
            file_name = "dns-servers-qmin_%s" % args.graph_output
            dns_trs_qmin.graph(target="> %s" % file_name)
            log.info("Wrote DNS servers traceroute graph to(If QMIN Enabled): %s" % file_name)

        try:
            web_tr, _ = traceroute_web_server(fqdn)
        except Exception as err:
            log.warning("Couldn't run traceroute: %s" % err)
            continue
        if args.graph_output is not None:
            file_name = "web-server_%s" % args.graph_output
            web_tr.graph(target="> %s" % file_name)
            log.info("Wrote web server traceroute graph to: %s" % file_name)

        log.info("Now comparing ASNs from all traceroute types.")
        dns_asns = asns_in_traceroute(dns_trs, asndb)
        dns_asns_qmin = asns_in_traceroute(dns_trs_qmin, asndb)
        web_asns = asns_in_traceroute(web_tr, asndb)
        stats.dns_asns += dns_asns
        stats.dns_asns_qmin += dns_asns_qmin
        stats.web_asns += web_asns

        asn_comparison(dns_asns, dns_asns_qmin, web_asns)

    determine_stats()

    return 0


if __name__ == "__main__":
 sys.exit(main())
