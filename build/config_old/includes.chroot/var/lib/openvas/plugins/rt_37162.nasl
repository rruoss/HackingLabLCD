###############################################################################
# OpenVAS Vulnerability Test
# $Id: rt_37162.nasl 15 2013-10-27 12:49:54Z jan $
#
# RT Session Fixation Vulnerability
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
tag_summary = "RT is prone to a session-fixation vulnerability.

Attackers can exploit this issue to hijack a user's session and gain
unauthorized access to the affected application.

The issue affects RT 3.0.0 through 3.8.5.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100386);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-09 13:16:50 +0100 (Wed, 09 Dec 2009)");
 script_bugtraq_id(37162);
 script_cve_id("CVE-2009-3585");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_tag(name:"risk_factor", value:"High");

 script_name("RT Session Fixation Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37162");
 script_xref(name : "URL" , value : "http://lists.bestpractical.com/pipermail/rt-announce/2009-November/000177.html");
 script_xref(name : "URL" , value : "http://lists.bestpractical.com/pipermail/rt-announce/2009-November/000176.html");
 script_xref(name : "URL" , value : "http://www.bestpractical.com/rt/");

 script_description(desc);
 script_summary("Determine if RT is prone to a session-fixation	vulnerability.");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("rt_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("www/", port, "/rt_tracker")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_in_range(version: vers, test_version: "3", test_version2: "3.8.5")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
