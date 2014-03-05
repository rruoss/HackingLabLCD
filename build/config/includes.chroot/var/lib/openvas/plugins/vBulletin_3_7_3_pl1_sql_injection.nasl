###############################################################################
# OpenVAS Vulnerability Test
# $Id: vBulletin_3_7_3_pl1_sql_injection.nasl 15 2013-10-27 12:49:54Z jan $
#
# vBulletin 'admincalendar.php' SQL Injection Vulnerability
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
tag_summary = "vBulletin is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in
  an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  Note that to succeed, the attacker must have an administrative
  account with 'calendar' administrator access.

  vBulletin 3.7.3.pl1 is vulnerable; other versions may also be affected.";

tag_solution = "Upgrade to newest Version of VBulletin.";

if (description)
{
 script_id(100020);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_bugtraq_id(32348);
 script_cve_id("CVE-2008-6256");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("vBulletin 'admincalendar.php' SQL Injection Vulnerability");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Determine if VBulletin 3.7.3.pl1 is running, which is known to be vulnerable to SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("vbulletin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("vBulletin/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

version = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(version)) exit(0);

matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$");

if (!isnull(matches)) {
 ver = matches[1];
 if ( ver <= "3.7.3.pl1" ) {
	security_hole(port:port);
	exit(0);
 }  
}  

exit(0);
