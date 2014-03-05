###############################################################################
# OpenVAS Vulnerability Test
# $Id: quicksilver_forums_32452.nasl 14 2013-10-27 12:33:37Z jan $
#
# Quicksilver Forums Local File Include and Arbitrary File Upload Vulnerabilities
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
tag_summary = "Quicksilver Forums is prone to a local file-include vulnerability and
an arbitrary-file-upload vulnerability because the application fails
to sufficiently sanitize user-supplied input.

An attacker can exploit these issues to upload arbitrary files onto
the webserver, execute arbitrary local files within the context of the
webserver, and obtain sensitive information. By exploiting the arbitrary-file-
upload and local file-include vulnerabilities at the same time, the
attacker may be able to execute remote code.

Quicksilver Forums 1.4.2 is vulnerable; other versions may also be
affected. Note that these issues affect only versions running on
Windows platforms.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100504);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-23 17:05:07 +0100 (Tue, 23 Feb 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-7064");
 script_bugtraq_id(32452);
 script_tag(name:"risk_factor", value:"High");

 script_name("Quicksilver Forums Local File Include and Arbitrary File Upload Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if Quicksilver Forums version is <= 1.4.2");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("os_fingerprint.nasl","quicksilver_forums_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/32452");
 script_xref(name : "URL" , value : "http://pdnsadmin.iguanadons.net/index.php?a=newspost&amp;t=85");
 script_xref(name : "URL" , value : "http://www.quicksilverforums.com/");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (host_runs("windows") != "yes") exit(0);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/quicksilver")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less_equal(version: vers, test_version: "1.4.2")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
