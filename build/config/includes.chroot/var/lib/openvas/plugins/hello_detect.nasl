# OpenVAS Vulnerability Test
# $Id: hello_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: DCN HELLO detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "The remote IP stack answers to an obsolete protocol.

Description :

The remote host is running HELLO, an obsolete routing protocol.
If possible, this IP protocol should be disabled.";

tag_solution = "If this protocol is not needed, disable it or filter incoming traffic going
to IP protocol #63.";

# See RFC 831 & gated source (hello.h)
# http://www.zvon.org/tmRFC/RFC891/Output/chapter2.html

if(description)
{
  script_id(11913);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");

  name = "DCN HELLO detection";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
 
  summary = "Sends an DCH HELLO Message";
  script_summary(summary);
  script_category(ACT_GATHER_INFO); 
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Service detection");
  script_require_keys("Settings/ThoroughTests");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

#
#                         1                   0 
#               5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
#          --- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# Fixed        |           Checksum            |
# Area         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |             Date              |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |                               |
#              +              Time             +
#              |                               |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |           Timestamp           |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |     Offset    |   Hosts (n)   |
#          --- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# Host         |          Delay Host 0         |
# Area         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |         Offset Host 0         |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#             ...                             ...
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |         Delay Host n-1        |
#              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              |         Offset Host n-1       |
#          --- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 
#                Figure 3. HELLO Message Format
# 

include('global_settings.inc');
include("network_func.inc");
##include("dump.inc");

if(TARGET_IS_IPV6())exit(0);
if (islocalhost() || ! thorough_tests ) exit(0); 

s = this_host();
v = eregmatch(pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9])+$", string: s);
if (isnull(v)) exit(0);

for (i = 1; i <=4; i++) a[i] = int(v[i]);

a1 = rand() % 256; a2 = rand() % 256;
s1 = rand() % 256; s2 = rand() % 256;

# Date is in RT-11 format, i.e. little endian, AFAIK. The date overflows
# in 2003 (!) so I suggest to tell them that we are at 2003-12-31 
# The source of gated gives more information than RFC 891. 2003-12-31 would
# give: 0x33FF; adding flags 0xC000 (Clock is unsynchronized) gives 0xF3FF

ms = ms_since_midnight();		# milliseconds since midnight
if (isnull(ms)) ms = rand();

r = raw_string(
	0, 0, 		# Checksum
	0xF3, 0xFF	# Date
	);
r += htons(ms);		# Time = ms since midnight
r  += raw_string(
	0, 0,		# Timestamp
	0,		# Offset (?)
	0 );		# Nb of hosts ??

ck = ip_checksum(data: r);
r2 = insstr(r, ck, 0, 1);

# HELLO is protocol 63
egp = forge_ip_packet(ip_v: 4, ip_hl: 5, ip_tos: 0, ip_p: 63, ip_ttl: 64,
			ip_off: 0, ip_src: this_host(),	data: r2);

f = "ip proto 63 and src " + get_host_ip();
for ( i = 0 ; i < 3 ; i ++ )
{
 r = send_packet(egp, pcap_active: TRUE, pcap_filter: f, pcap_timeout:1);
 if ( r ) break;
}

if (isnull(r)) exit(0);

##hl = ord(r[0]) & 0xF; hl *= 4;
##hello = substr(r, hl);
##dump(dtitle: "hello", ddata: hello);

#ck = ip_checksum(data: hello);

security_warning(port: 0, proto: "hello");
