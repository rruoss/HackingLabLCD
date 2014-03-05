###############################################################################
# OpenVAS Vulnerability Test
# $Id: Chipmunk_guestbook_sql_injection_and_xss.nasl 15 2013-10-27 12:49:54Z jan $
#
# Chipmunk Guestbook Index.PHP SQL Injection Vulnerability
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
tag_summary = "Chipmunk Guestbook is prone to an SQL-injection vulnerability
  because it fails to properly sanitize user-supplied input before
  using it in an SQL query.

  A successful exploit could allow an attacker to compromise the
  application, access or modify data, or exploit vulnerabilities in
  the underlying database.";


if (description)
{
 script_id(100039);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
 script_bugtraq_id(18195);
 script_cve_id("CVE-2008-6368");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Chipmunk Guestbook Index.PHP SQL Injection Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if Chipmunk Guestbook is prone to SQL Injection and Cross Site Scripting");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/18195");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list("/guestbook",cgi_dirs());

foreach d (dir)
{ 
 url = string(d, "/index.php?start=<script>alert(document.cookie)</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;
 if (
     egrep(pattern:".*You have an error in your SQL syntax.*", string: buf) &&
     egrep(pattern:".*<script>alert\(document.cookie\)</script>.*", string: buf)
    )
     
 	{    
       	  security_hole(port:port);
          exit(0);
        }
}

exit(0);
