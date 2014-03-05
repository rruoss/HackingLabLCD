###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_38562.nasl 18 2013-10-27 14:14:13Z jan $
#
# OpenSSL 'bn_wexpend()' Error Handling Unspecified Vulnerability
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
tag_summary = "OpenSSL is prone to an unspecified vulnerability in bn_wexpend().

According to its banner, OpenVAS has discovered that the remote Webserver is
using a version prior to OpenSSL 0.9.8m which is vulnerable.";

tag_solution = "The vendor has released updates. Please see the references for more
information.";

if (description)
{
 script_id(100527);
 script_bugtraq_id(38562);
 script_cve_id("CVE-2009-3245");
 script_version ("1.0-$Revision: 18 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("OpenSSL 'bn_wexpend()' Error Handling Unspecified Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "


";
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38562");
 script_xref(name : "URL" , value : "http://openssl.org/");

 script_description(desc);
 script_summary("Determine if installed OpenSSL version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

     
include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);

if(!banner || "OpenSSL/" >!< banner)exit(0);

version = eregmatch(pattern: "OpenSSL/([a-zA-Z0-9.]+)", string:  banner);
if(isnull(version[1]))exit(0);

vers = version[1];

vers = ereg_replace(string:vers, pattern:"([a-z]$)", replace:".\1");

if(vers =~ "^0\.9\.") {

  if(!isnull(vers)) {

    if(version_is_less(version: vers, test_version: "0.9.8.m")) {
        security_hole(port:port);
        exit(0);
    }
 
  }
}

exit(0);

