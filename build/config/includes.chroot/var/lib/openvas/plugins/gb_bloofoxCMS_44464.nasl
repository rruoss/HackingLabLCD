###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bloofoxCMS_44464.nasl 14 2013-10-27 12:33:37Z jan $
#
# bloofoxCMS 'gender' Parameter SQL Injection Vulnerability
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
tag_summary = "bloofoxCMS is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in
an SQL query.

Exploiting this issue can allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

bloofoxCMS 0.3.5 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100877);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-28 13:41:07 +0200 (Thu, 28 Oct 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4870");
 script_bugtraq_id(44464);

 script_name("bloofoxCMS 'gender' Parameter SQL Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44464");
 script_xref(name : "URL" , value : "http://www.bloofox.com/cms/");
 script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/sql_injection_in_bloofoxcms_registration_plugin.html");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed bloofoxCMS version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("bloofoxCMS_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"bloofoxCMS")) {

  if(version_is_equal(version: vers, test_version: "0.3.5")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
