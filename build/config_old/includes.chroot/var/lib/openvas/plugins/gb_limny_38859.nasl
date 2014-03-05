###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_38859.nasl 14 2013-10-27 12:33:37Z jan $
#
# Limny 2.01 Multiple Remote Vulnerabilities
#
# Authors:
# Michael Meyer
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
tag_summary = "Limny is prone to multiple remote vulnerabilities, including:

- Multiple HTML-injection vulnerabilities
- Multiple SQL-injection vulnerabilities
- Multiple security-bypass vulnerabilities
- Multiple cross-site scripting vulnerabilities.

The attacker may exploit these issues to compromise the application,
execute arbitrary code, steal cookie-based authentication credentials,
gain unauthorized access to the application, modify data, or exploit
latent vulnerabilities in the underlying database. Other attacks are
also possible.

Limny 2.01 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100545);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-22 19:12:13 +0100 (Mon, 22 Mar 2010)");
 script_bugtraq_id(38859);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Limny 2.01 Multiple Remote Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38859");
 script_xref(name : "URL" , value : "http://www.limny.org/");

 script_description(desc);
 script_summary("Determine if Limny version is 2.01");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_limny_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"Limny")) {

  if(version_is_equal(version: vers, test_version: "2.01")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
