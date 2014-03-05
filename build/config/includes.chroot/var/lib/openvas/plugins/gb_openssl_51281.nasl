###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_51281.nasl 12 2013-10-27 11:15:33Z jan $
#
# OpenSSL Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "OpenSSL prone to multiple security vulnerabilities.

An attacker may leverage these issues to obtain sensitive information,
cause a denial-of-service condition and perform unauthorized actions.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103394);
 script_bugtraq_id(51281);
 script_cve_id("CVE-2011-4108","CVE-2011-4109","CVE-2011-4576","CVE-2011-4577","CVE-2011-4619","CVE-2012-0027");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("OpenSSL Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51281");
 script_xref(name : "URL" , value : "http://www.openssl.org");
 script_xref(name : "URL" , value : "http://www.openssl.org/news/secadv_20120104.txt");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-01-20 11:28:16 +0100 (Fri, 20 Jan 2012)");
 script_description(desc);
 script_summary("Determine if installed OpenSSl version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);

if(!banner || "OpenSSL/" >!< banner)exit(0);

version = eregmatch(pattern: "OpenSSL/([^ ]+)", string: banner);
if(isnull(version[1]))exit(0);

vers = version[1];
vers = ereg_replace(string:vers, pattern:"([a-z]$)", replace:".\1");

if(!isnull(vers)) {

  if(vers =~ "1\.0\.") {
    if(version_is_less(version:vers, test_version:"1.0.0.f")) {
      security_hole(port:port);
      exit(0);
    }
  }

  if(vers =~ "0\.9\.") {
    if(version_is_less(version:vers, test_version:"0.9.8.s")) {
      security_hole(port:port);
      exit(0);
    }
  }



}

exit(0);
