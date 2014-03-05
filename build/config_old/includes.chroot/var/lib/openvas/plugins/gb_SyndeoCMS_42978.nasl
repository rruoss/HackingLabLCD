###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SyndeoCMS_42978.nasl 14 2013-10-27 12:33:37Z jan $
#
# SyndeoCMS Local File Include, Cross Site Scripting, and HTML Injection Vulnerabilities
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
tag_summary = "SyndeoCMS is prone to a local file-include, a cross-site scripting,
and an HTML-injection vulnerability because the application fails to
properly sanitize user-supplied input.

Exploiting the local file-include issue allows remote attackers
to view or execute local files within the context of the
webserver process.

An attacker may leverage the cross-site scripting and HTML-injection
issues to execute arbitrary script code in the browser of an
unsuspecting user in the context of the affected site. This may allow
the attacker to steal cookie-based authentication credentials, render
how the site is displayed, or to launch other attacks.

SyndeoCMS version 2.8.02 and prior are vulnerable.";


if (description)
{
 script_id(100784);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-06 14:44:23 +0200 (Mon, 06 Sep 2010)");
 script_bugtraq_id(42978);

 script_name("SyndeoCMS Local File Include, Cross Site Scripting, and HTML Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42978");
 script_xref(name : "URL" , value : "http://www.syndeocms.org/");

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed SyndeoCMS version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_SyndeoCMS_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"syndeocms")) {
  if(version_is_less_equal(version: vers, test_version: "2.8.02")) {
      security_warning(port:port);
      exit(0);
  }
}

exit(0);
