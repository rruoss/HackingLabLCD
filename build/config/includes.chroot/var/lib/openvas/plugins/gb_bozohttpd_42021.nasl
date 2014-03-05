###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bozohttpd_42021.nasl 14 2013-10-27 12:33:37Z jan $
#
# bozohttpd Security Bypass Vulnerability
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
tag_summary = "bozohttpd is prone to a security-bypass vulnerability.

An attacker can exploit this issue to bypass certain security
restrictions and gain access to restricted content. This can lead to
other attacks.

bozohttpd 20090522 and 20100509 are vulnerable; other versions may
also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100750);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-09 13:36:05 +0200 (Mon, 09 Aug 2010)");
 script_bugtraq_id(42021);
 script_cve_id("CVE-2010-2195","CVE-2010-2320");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("bozohttpd Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42021");
 script_xref(name : "URL" , value : "https://bugs.launchpad.net/ubuntu/+source/bozohttpd/+bug/582473");
 script_xref(name : "URL" , value : "http://www.eterna.com.au/bozohttpd/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed bozohttpd version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

     
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "bozohttpd" >!< banner)exit(0);

version = eregmatch(pattern:"Server: bozohttpd/([0-9]+)", string:banner);
if(isnull(version[1]))exit(0);

vers = version[1];
if(!isnull(vers)) {

  if(version_is_equal(version: vers, test_version: "20090522") ||
     version_is_equal(version: vers, test_version: "20100509")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

