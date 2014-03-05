# OpenVAS Vulnerability Test
# $Id: egp_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: EGP detection
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

The remote host is running EGP, an obsolete routing protocol.

If possible, this IP protocol should be disabled.";

tag_solution = "If this protocol is not needed, disable it or filter incoming traffic going
to IP protocol #8";

# See RFC 827 & RFC 888

if(description)
{
  script_id(11908);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");

  name = "EGP detection";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
 
  summary = "Sends an EGP Neighbor Acquisition Message";
  script_summary(summary);
  script_category(ACT_GATHER_INFO); 
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Service detection");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


##include("dump.inc");
include('global_settings.inc');
include("network_func.inc");
if (islocalhost() || ! thorough_checks) exit(0);
if(TARGET_IS_IPV6())exit(0);

s = this_host();
v = eregmatch(pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9])+$", string: s);
if (isnull(v)) exit(0);
for (i = 1; i <=4; i++) a[i] = int(v[i]);

a1 = rand() % 256; a2 = rand() % 256;
s1 = rand() % 256; s2 = rand() % 256;

r = raw_string(	2,	# EGP version
		3,	# Type
		0,	# Code = Neighbor Acquisition Request
		0,	# Info (not used here)
		0, 0,	# checksum
		a1, a2,	# Autonomous system
		s1, s2,	# Identification
		0, 30,	# NR Hello Interval
		0, 120	# NR Poll Interval
	);

ck = ip_checksum(data: r);
r2 = insstr(r, ck, 4, 5);

egp = forge_ip_packet(ip_v: 4, ip_hl: 5, ip_tos: 0, ip_p: 8, ip_ttl: 64,
			ip_off: 0, ip_src: this_host(),	data: r2);

f = "ip proto 8 and src " + get_host_ip();
for ( i = 0 ; i < 3 ; i ++ )
{
 r = send_packet(egp, pcap_active: TRUE, pcap_filter: f, pcap_timeout:1);
 if ( r ) break;
}
if ( r == NULL ) exit(0);

hl = ord(r[0]) & 0xF; hl *= 4;
egp = substr(r, hl);
if (ord(egp[0]) == 2 && ord(egp[1]) == 3 && ord(egp[2]) <= 4)
  security_warning(port: 0, proto: "egp");
