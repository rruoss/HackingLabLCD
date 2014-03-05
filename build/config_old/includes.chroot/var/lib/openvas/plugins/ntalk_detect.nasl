# OpenVAS Vulnerability Test
# $Id: ntalk_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Detect talkd server port and protocol version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Minor modifications by Renaud Deraison <deraison@cvs.nessus.org>, namely :
#	- the report is more comprehensive
#	- the script exits if it gets no answer from the
#	  remote host at first time
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
tag_summary = "The remote host is running a 'talkd' daemon.

talkd is the server that notifies a user that someone else wants to initiate 
a conversation with him.";

tag_solution = "Disable talkd access from the network by adding the approriate rule on your 
 firewall. If you do not need talkd, comment out the relevant line in 
 /etc/inetd.conf and restart the inetd process.";
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "

";
if(description)
{
 script_id(10168);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-1999-0048");
 name = "Detect talkd server port and protocol version";
 script_name(name);
 
 script_description(desc);
 
 summary = "Detect talkd server port and protocol version";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2000 SecuriTeam");
 script_family("Service detection");
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.cert.org/advisories/CA-1997-04.html");
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

 if(!(get_udp_port_state(518)))exit(0);
 
 srcaddr = this_host();
 a1 = ereg_replace(pattern:"([0-9]*)\.[0-9]*\.[0-9]*\.[0-9]*",
                  string:srcaddr,
                  replace:"\1"); a1 = a1 % 255;
                  
 a2 = ereg_replace(pattern:"[0-9]*\.([0-9]*)\.[0-9]*\.[0-9]*",
                  string:srcaddr,
                  replace:"\1"); a2 = a2 % 255;
                  

 a3 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.([0-9]*)\.[0-9]*",
                  string:srcaddr,
                  replace:"\1"); a3 = a3 % 255;
                  
                  
 a4 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)",
                  string:srcaddr,
                  replace:"\1"); a4 = a4 % 255;
		  
 dstaddr = get_host_ip();

 b1 = ereg_replace(pattern:"([0-9]*)\.[0-9]*\.[0-9]*\.[0-9]*",
                  string:dstaddr,
                  replace:"\1"); b1 = b1 % 255;
                  
 b2 = ereg_replace(pattern:"[0-9]*\.([0-9]*)\.[0-9]*\.[0-9]*",
                  string:dstaddr,
                  replace:"\1"); b2 = b2 % 255;
                  

 b3 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.([0-9]*)\.[0-9]*",
                  string:dstaddr,
                  replace:"\1"); b3 = b3 % 255;
                  
                  
 b4 = ereg_replace(pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)",
                  string:dstaddr,
                  replace:"\1"); b4 = b4 % 255;
		  
		  
 sendata = raw_string( 
 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x02, 0x00, 0x00, a1,   a2, 
 a3,     a4, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x04, 
 b1,     b2,   b3,   b4, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x30, 0x9F, 0x72, 0x6F, 0x6F, 0x74, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x72, 0x6F, 0x6F, 0x74, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
#  1     2     3     4     5     6     7     8     9     10

 dstport = 518;
 soc = open_sock_udp(dstport);
 if( ! soc ) exit(0);
 send(socket:soc, data:sendata);
 result = recv(socket:soc, length:4096);
 if (result)
 {
  banner = "talkd protocol version: ";
  banner = string(banner, ord(result[0]));
  data = desc + string("\n\n") + banner;
  register_service(port: 518, ipproto: "udp", proto: "ntalk");
  security_hole(port:518, data:data, protocol:"udp");
 }

 close(soc);
