###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icmp_timestamps.nasl 13 2013-10-27 12:16:33Z jan $
#
# ICMP Timestamp
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "The remote host responded to an ICMP timestamp request. The Timestamp Reply is
an ICMP message which replies to a Timestamp message. It consists of the
originating timestamp sent by the sender of the Timestamp as well as a receive
timestamp and a transmit timestamp. This information could theoretically be used
to exploit weak time-based random number generators in other services.";

if (description)
{
 
 script_id(103190);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-07-15 13:32:07 +0200 (Fri, 15 Jul 2011)");
 script_cve_id("CVE-1999-0524");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:N");

desc = "
 Summary:
 " + tag_summary;


 script_name("ICMP Timestamp Detection");
 script_description(desc);
 script_summary("Checks if the remote host answers to ICMP Timestamp requests");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("ping_host.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.ietf.org/rfc/rfc0792.txt");
 exit(0);
}

if(islocalhost())exit(0);
if(TARGET_IS_IPV6())exit(0);

host = this_host();

ip = forge_ip_packet(ip_hl:5, ip_v:4, ip_off:0, ip_id:9, ip_tos:0, ip_p:IPPROTO_ICMP, ip_len:20, ip_src:host, ip_ttl:255);
icmp = forge_icmp_packet(ip:ip,icmp_type:13, icmp_code:0, icmp_seq:1, icmp_id:1);

filter = string("icmp and src host ", get_host_ip(), " and dst host ", host, " and icmp[0:1] = 14");

for( i=0; i<5; i++ ) {

 res = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);

 if(res) {

   type = get_icmp_element(icmp:res, element:"icmp_type");
   code = get_icmp_element(icmp:res, element:"icmp_code");

   if(type == 14 && code == 0) {

     log_message(port:0, protocol:"icmp");
     exit(0);
   
   }
  }
}
