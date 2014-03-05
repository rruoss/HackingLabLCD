###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_46787.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla! Prior to 1.6.1 Multiple Security Vulnerabilities
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
tag_summary = "Joomla! is prone to multiple security vulnerabilities including:

An SQL-injection issue
A path-disclosure vulnerability
Multiple cross-site scripting issues
Multiple information-disclosure vulnerabilities
A URI-redirection vulnerability
A security-bypass vulnerability
A cross-site request-forgery vulnerability
A denial-of-service vulnerability

An attacker can exploit these vulnerabilities to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie-based authentication credentials,
disclose or modify sensitive information, exploit latent
vulnerabilities in the underlying database, deny service to legitimate
users, redirect a victim to a potentially malicious site, or perform
unauthorized actions. Other attacks are also possible.

Versions prior to Joomla! 1.6.1 are vulnerable.";

tag_solution = "The vendor released a patch. Please see the references for more
information.";

if (description)
{
 script_id(103114);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-09 13:38:24 +0100 (Wed, 09 Mar 2011)");
 script_bugtraq_id(46787);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Joomla! Prior to 1.6.1 Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46787");
 script_xref(name : "URL" , value : "http://www.joomla.org/announcements/release-news/5350-joomla-161-released.html");
 script_xref(name : "URL" , value : "http://www.joomla.org/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Joomla version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("joomla/installed");
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

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"joomla")) {

  if(version_is_less(version: vers, test_version: "1.6.1")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
