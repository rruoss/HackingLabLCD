###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_45123.nasl 14 2013-10-27 12:33:37Z jan $
#
# Awstats Configuration File Remote Arbitrary Command Execution Vulnerability
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
tag_summary = "Awstats is prone to an arbitrary command-execution vulnerability. This
issue is due to a failure in the application to properly sanitize user-
supplied input.

An attacker can exploit this vulnerability to execute arbitrary
shell commands in the context of the webserver process. This may
help attackers compromise the underlying system; other attacks are
also possible.

Awstats < 7.0 is vulnerable;";


if (description)
{
 script_id(100925);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
 script_cve_id("CVE-2010-4367", "CVE-2010-4368");
 script_bugtraq_id(45123);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Awstats Configuration File Remote Arbitrary Command Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45123");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/870532");
 script_xref(name : "URL" , value : "http://www.exploitdevelopment.com/Vulnerabilities/2010-WEB-001.html");
 script_xref(name : "URL" , value : "http://awstats.sourceforge.net/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Awstats version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("awstats_detect.nasl","os_fingerprint.nasl","gb_apache_tomcat_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

if(!get_kb_item(string("www/", port, "/ApacheTomcat")))exit(0);

if (host_runs("windows") != "yes") { # "no" or "unknown"
  exit(0);
}

if(vers = get_version_from_kb(port:port,app:"awstats")) {

  if(version_is_less_equal(version: vers, test_version: "6.95")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
