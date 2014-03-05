###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_family_connections_40043.nasl 14 2013-10-27 12:33:37Z jan $
#
# Family Connections 2.2.3 Multiple SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Family Connections is prone to multiple SQL-injection vulnerabilities
because it fails to sufficiently sanitize user-supplied data before
using it in an SQL query.

Exploiting these issues could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Family Connections 2.2.3 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100634);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-11 20:07:01 +0200 (Tue, 11 May 2010)");
 script_bugtraq_id(40043);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Family Connections 2.2.3 Multiple SQL Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40043");
 script_xref(name : "URL" , value : "http://www.familycms.com/index.php");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if the remote Family Connections version is prone to multiple SQL-injection vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("family_connections_detect.nasl");
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

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"FamilyConnections")) {

  if(version_is_equal(version: vers, test_version: "2.2.3")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
