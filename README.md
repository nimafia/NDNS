# DNS delegation path traceroute with supporting QNAME Minimization

ddprtrQM is developed version of ddptr >> https://github.com/NullHypothesis/ddptr/

ddptrQM runs (i) UDP traceroutes to all DNS servers that are in the DNS delegation path for a fully qualified domain name (FQDN), (ii) UDP traceroutes to all DNS servers that are in the DNS delegation path and can see the full QNAME of original DNS Request if user want to use QNAME minimization and (iii) TCP traceroutes to port 80 of the same FQDN. Then, the tool maps the IP addresses of all intermediate hops to autonomous system numbers and determines the set intersections.

ddptrQM is useful for traffic analysis experiments, i.e., quantifying the threat of AS-level adversaries.
Requirements

You will need the Python modules scapy and pyasn.

# Example

The tool takes as input a FQDN and an ASN database. Instructions on how to build such a database are online.

Here is a simple example:

 > $ sudo ./ddptrQM --fqdn youtube.com /path/to/asn/database

In my case, the tool tells me:

2017-09-12 12:33:52,833 [INFO]: Now handling FQDN 1 of 1: youtube.com


2017-09-12 12:33:52,833 [INFO]: Tracing delegation path for FQDN youtube.com using 8.8.8.8.


2017-09-12 12:33:55,037 [INFO]: Extracting DNS servers from dig's output


2017-09-12 12:33:55,038 [INFO]: DNS servers in dig trace: 192.58.128.30, 192.42.93.30, 216.239.34.10


2017-09-12 12:33:55,038 [INFO]: Extracting DNS servers that see the full QNAME(If we use QNAME Minimization) from dig's output.


2017-09-12 12:33:55,039 [INFO]: DNS servers that can see full QNAME in dig trace(If QMIN Enabled): 192.42.93.30, 216.239.34.10


2017-09-12 12:33:55,039 [INFO]: Running UDP traceroutes to 3 servers.


2017-09-12 12:33:57,284 [INFO]: Running UDP traceroutes to 2 servers.


2017-09-12 12:33:59,434 [INFO]: Running TCP traceroute to port 80 of: youtube.com


2017-09-12 12:34:01,527 [INFO]: Now comparing ASNs from all traceroute types.


2017-09-12 12:34:01,530 [INFO]: 5 ASNs in DNS hops: 15169,20764,7342,36622,24940


2017-09-12 12:34:01,530 [INFO]: 4 (if qmin enabed)ASNs in DNS hops: 15169,7342,36622,24940


2017-09-12 12:34:01,530 [INFO]: 2 ASNs in web hops: 15169,24940


2017-09-12 12:34:01,530 [INFO]: 2 intersections between web and DNS ASNs: 15169,24940


2017-09-12 12:34:01,530 [INFO]: 2 (If QMIN Enabled)intersections between web and DNS ASNs: 15169,24940


2017-09-12 12:34:01,530 [INFO]: 3 ASNs in DNS but not in web ASNs: 20764,7342,36622


2017-09-12 12:34:01,530 [INFO]: 2 ASNs in DNS but not in web ASNs (With QNAME Minimization): 7342,36622

2017-09-12 12:34:01,530 [INFO]: 0 ASNs in web but not in DNS ASNs: 

2017-09-12 12:34:01,530 [INFO]: 0 ASNs in web but not in DNS ASNs (IF QMIN Enabled): 

2017-09-12 12:34:01,530 [INFO]: dns=(5)15169|20764|7342|36622|24940, dns-q=(4)15169|7342|36622|24940, web=(2)15169|24940 || only-dns=(3)20764|7342|36622, only-web=(0) || If QNAME Minimization Enabled ==> only-dns-q=(2)7342|36622, only-web-q=(0)

2017-09-12 12:34:01,530 [INFO]: Exposure-nq (Without QMIN) is 0.600


2017-09-12 12:34:01,530 [INFO]: Exposure-q (With QNAME Minimization) is 0.500

2017-09-12 12:34:01,531 [INFO]: Total traversed DNS ASes: 26, DNS ASes(If QMIN Enabled): 19, web ASes: 13 (50.00%) (68.42%)

2017-09-12 12:34:01,531 [INFO]: Unique DNS ASNs: 20764,24940,36622,7342,15169

2017-09-12 12:34:01,531 [INFO]: (If QMIN Enabled)Unique DNS ASNs: 15169,24940,36622,7342

2017-09-12 12:34:01,531 [INFO]: Unique web ASNs: 15169,24940

2017-09-12 12:34:01,531 [INFO]: Total unique traversed DNS ASes: 5, Total unique traversed DNS ASes(If QMIN Enabled): 2 total 
unique traversed web ASes: 4 (2.00%) total unique traversed web ASes(If QMIN Enabled): 40 (50.00%)

2017-09-12 12:34:01,531 [INFO]: Unique ASes traversed only for DNS: 3, unique ASes only traversed for web: 0 (0.00%), || If QMIN
Enabled => Unique ASes traversed only for DNS: 2, unique ASes onlytraversed for web: 0 (0.00%)


You can also use the parameter --graph-output to generate traceroute visualisations...
