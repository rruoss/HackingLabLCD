# OpenVAS Vulnerability Test
# $Id: nds_web_based_browsing.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Novell Web Server NDS Tree Browsing
#
# Authors:
# Noam Rathaus <noamr@securiteam.com> 
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com> 
# Copyright (C) 2001 SecuriTeam
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
tag_summary = "The Novell Web Server default ndsobj.nlm CGI (LCGI) was 
detected. This CGI allows browsing of the NDS Tree without any need for 
authentication.

Gaining access to the NDS Tree reveals sensitive information to an attacker.";

tag_solution = "Configure your Novell Web Server to block access to this CGI,
or delete it if you do not use it.

For More Information: http://www.securiteam.com/securitynews/5XP0L1555W.html";


if(description)
{
 script_id(10739); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(484);
 script_cve_id("CVE-1999-1020");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Novell Web Server NDS Tree Browsing";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Novell Web Server NDS Tree Browsing";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 family = "Web application abuses";
 script_family(family);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
 
 dir[0] = "/lcgi";
 dir[1] = "/lcgi-bin";
 dir[2] = "/LCGI";
 dir[3] = "/apage/lcgi-bin";

 port = get_http_port(default:80);

 

if (get_port_state(port))
{
  for(i=0;dir[i];i=i+1)
  {
  data = http_get(item:dir[i], port:port);
  resultrecv = http_keepalive_send_recv(port:port, data:data);
  if(resultrecv == NULL ) exit(0);
  if ("Available NDS Trees" >< resultrecv)
  {
    security_hole(port:port);
    exit(0);
  }
 }
}
