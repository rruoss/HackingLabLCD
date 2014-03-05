###############################################################################
# OpenVAS Vulnerability Test
# $Id: bugzilla_36371.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Bugzilla 'Bug.search()' WebService Function SQL Injection Vulnerability
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
tag_summary = "Bugzilla is prone to an SQL-injection vulnerability because it fails
to sufficiently sanitize user-supplied data before using it in an SQL
query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

The following versions are affected:

Bugzilla 3.3.2 through 3.4.1 Bugzilla 3.5";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100286);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-02 19:48:14 +0200 (Fri, 02 Oct 2009)");
 script_bugtraq_id(36371);
 script_cve_id("CVE-2009-3125");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Mozilla Bugzilla 'Bug.search()' WebService Function SQL Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36371");
 script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=515191");
 script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.0.8/");
 script_xref(name : "URL" , value : "http://www.bugzilla.org");

 script_description(desc);
 script_summary("Determine if Bugzilla is prone to an SQL-injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("bugzilla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/bugzilla/version")))exit(0);

if(!isnull(version) && version >!< "unknown") {

  if(version_in_range(version:version, test_version:"3.4", test_version2:"3.4.1") ||
     version_in_range(version:version, test_version:"3.3", test_version2:"3.3.4") ||
     version_is_equal(version:version, test_version:"3.5")) {
      security_hole(port:port);
      exit(0);
  }
}

exit(0);
