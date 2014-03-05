# OpenVAS Vulnerability Test
# $Id: tcp_timestamps.nasl 80 2013-11-27 12:56:15Z thomas-rotter $
# Description: TCP timestamps
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2007 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");

if (description)
{
  script_id(80091);
  script_version("$Revision: 80 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-27 13:56:15 +0100 (Wed, 27 Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");

  script_name("TCP timestamps");
  script_summary("Look at RFC1323 TCP timestamps");

  script_xref(name : "URL" , value : "http://www.ietf.org/rfc/rfc1323.txt");

  tag_summary =
"The remote host implements TCP timestamps and therefore allows to compute
the uptime.";

  tag_vuldetect =
"Special IP packets are forged and sent with a little delay in between to the
target IP. The responses are searched for a timestamps. If found, the
timestamps are reported.";

  tag_solution =
"To disable TCP timestamps on linux add the line 'net.ipv4.tcp_timestamps = 0' to
/etc/sysctl.conf. Execute 'sysctl -p' to apply the settings at runtime.

To disable TCP timestamps on Windows execute 'netsh int tcp set global timestamps=disabled'

Starting with Windows Server 2008 and Vista, the timestamp can not be completely disabled.

The default behavior of the TCP/IP stack on this Systems is, to not use the 
Timestamp options when initiating TCP connections, but use them if the TCP peer 
that is initiating communication includes them in their synchronize (SYN) segment.

See also: http://www.microsoft.com/en-us/download/details.aspx?id=9152";

  tag_affected =
"TCP/IPv4 implementations that implement RFC1323.";

  tag_insight =
"The remote host implements TCP timestamps, as defined by RFC1323.";

  tag_impact =
"A side effect of this feature is that the uptime of the remote
host can sometimes be computed.";

desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);

  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_add_preference(name: "Delay (seconds):", value: "1", type: "entry");
  script_copyright("This script is Copyright (C) 2007 Michel Arboi");

  exit(0);
}


include("global_settings.inc");
include("network_func.inc");

if ( TARGET_IS_IPV6()) exit(0);

function test(seq)
{
 local_var ip, tcp, options, filter, ms, r, sport;

 sport = rand() % (65536 - 1024) + 1024;
 ip = forge_ip_packet(ip_v: 4, ip_hl: 5, ip_tos: 0,
                      ip_len: 20, ip_id: rand(), ip_p: IPPROTO_TCP,
                      ip_ttl: 255, ip_off: 0, ip_src: saddr);

 options = strcat(
'\x08',         # Timestamp option
'\x0A',         # length
htonl(n: seq),  # TSVal
'\0\0\0\0',     # TSecr is invalid as ACK is not set
'\x01\x01');    # NOP padding

 tcp = forge_tcp_packet(ip: ip, th_sport: sport, th_dport: dport,
                        th_flags: TH_SYN, th_seq: rand(),
                        th_ack: 0, th_x2: 0, th_off: 8,
                        th_win: 512, th_urp: 0, data: options);


 filter = strcat('tcp and src ', daddr, ' and dst ', saddr, ' and src port ', dport, ' and dst port ', sport);
 r = send_packet(tcp, pcap_active: TRUE, pcap_filter: filter);
 ms = ms_since_midnight();

 tsval = tcp_extract_timestamp(ip: r);
 if (isnull(tsval)) return NULL;
 return make_list(ms, tsval);
}

function tcp_extract_timestamp(ip)
{
 local_var hl, hlen, tcp, flags, opt, lo, i, n, tsval, tsecr, len;
 if (isnull(ip) || strlen(ip) < 20) return NULL;

 hl = ord(ip[0]);
 hlen = (hl & 0xF) * 4;
 tcp = substr(ip, hlen);

### dump(ddata: i, dtitle: 'IP'); dump(ddata: tcp, dtitle: 'TCP');

 if (strlen(tcp) <= 20) return NULL;
 flags = ord(tcp[14]);
 if (! (flags & TH_ACK)) return NULL;

 opt = substr(tcp, 20);
###dump(ddata: opt, dtitle: 'TCP options');
 lo = strlen(opt);
 for (i = 0; i < lo; )
 {
  n = ord(opt[i]);
  if (n == 8) # Timestamp
  {
   tsval = ntohl(n: substr(opt, i+2, i+5));
   tsecr = ntohl(n: substr(opt, i+6, i+9));
   debug_print(level: 2, "TSVal=", tsval, " TSecr=", tsecr, "\n");
   return tsval;
  }
  else if (n == 1) # NOP
   i ++;
  else
  {
   len = ord(opt[i+1]);
   if ( len == 0 ) break;
   i += len;
  }
 }
 return NULL;
}

####

dport = get_host_open_port();
if (! dport) exit(0);

daddr = get_host_ip();
saddr = this_host();

v1 = test(seq: 1);

if (isnull(v1)) exit(0);

# A linear regression would not be more precise and NASL is definitely not
# designed for computation! We would need floating point.
delay = script_get_preference("Delay (seconds):");
if(!delay || int(delay)<1) {
  delay=1; 
}

sleep(delay);

v2 = test(seq: 2);
if (isnull(v2)) exit(1); # ???

dms = v2[0] - v1[0];
dseq = v2[1] - v1[1];

result = 'It was detected that the host implements RFC1323.\n\n' +
         'The following timestamps were retrieved with a delay of ' +
         delay + ' seconds in-between:\n' +
         'Paket 1: ' + v1[1] + '\n' +
         'Paket 2: ' + v2[1] + '\n\n';

security_warning(data: result);

