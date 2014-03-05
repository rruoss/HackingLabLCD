###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sql_ledger_49270.nasl 13 2013-10-27 12:16:33Z jan $
#
# SQL-Ledger SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "LedgerSMB and SQL-Ledger are prone to an SQL-injection vulnerability
because the application fails to properly sanitize user-supplied input
before using it in an SQL query.

A successful exploit may allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_id(103226);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-08-25 15:23:29 +0200 (Thu, 25 Aug 2011)");
 script_bugtraq_id(49270);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("SQL-Ledger SQL Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49270");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/ledger-smb/files/Development%20Snapshots/1.2.25-rc1/");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/ledger-smb/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519383");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed SQL-Ledger version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_sql_ledger_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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

if(vers = get_version_from_kb(port:port,app:"SQL-Ledger")) {

  if(version_is_less(version: vers, test_version: "2.8.34")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
