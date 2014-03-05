###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_49356.nasl 13 2013-10-27 12:16:33Z jan $
#
# Squid Proxy Gopher Remote Buffer Overflow Vulnerability
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
tag_summary = "Squid Proxy is prone remote buffer-overflow vulnerability affects the
Gopher-to-HTML functionality.

An attacker can exploit this issue to execute arbitrary code with the
privileges of the vulnerable application. Failed exploit attempts will
result in a denial-of-service condition.";

tag_solution = "The vendor released an update. Please see the references for more
information.";

if (description)
{
 script_id(103233);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-08-30 14:29:55 +0200 (Tue, 30 Aug 2011)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3205");
 script_bugtraq_id(49356);

 script_name("Squid Proxy Gopher Remote Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49356");
 script_xref(name : "URL" , value : "http://www.squid-cache.org/");
 script_xref(name : "URL" , value : "http://www.squid-cache.org/Advisories/SQUID-2011_3.txt");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Squid version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_squid_detect.nasl");
 script_require_ports("Services/www", 3128,8080);
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

port = get_http_port(default:3128);
if(!get_port_state(port))exit(0);

if(vers = get_version_from_kb(port:port,app:"Squid")) {

  if(version_in_range(version: vers, test_version: "3.2.0", test_version2: "3.2.0.10") ||
     version_is_less(version: vers, test_version: "3.1.15")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
