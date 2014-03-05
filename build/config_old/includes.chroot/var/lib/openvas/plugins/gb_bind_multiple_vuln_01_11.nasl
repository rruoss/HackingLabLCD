###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_multiple_vuln_01_11.nasl 13 2013-10-27 12:16:33Z jan $
#
# ISC BIND 9 'RRSIG' Record Type Negative Cache Remote Denial of Service Vulnerability
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
tag_summary = "ISC BIND is prone to multiple Vulnerabilities.

1.
A remote denial-of-service vulnerability.
An attacker can exploit this issue to cause the affected service to
crash, denying service to legitimate users.

2.
A security vulnerability that affects the integrity security property
of the application.

BIND versions 9.6.2 to 9.6.2-P2, 9.6-ESV to 9.6-ESV-R2 and 9.7.0 to
9.7.2-P2 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103030);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-14 14:24:22 +0100 (Fri, 14 Jan 2011)");
 script_bugtraq_id(45133,45137);
 script_cve_id("CVE-2010-3613","CVE-2010-3614");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

 script_name("ISC BIND 9 'RRSIG' Record Type Negative Cache Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45133");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45137");
 script_xref(name : "URL" , value : "https://www.isc.org/software/bind/advisories/cve-2010-3613");
 script_xref(name : "URL" , value : "https://www.isc.org/software/bind/advisories/cve-2010-3614");
 script_xref(name : "URL" , value : "http://www.isc.org/products/BIND/");
 script_xref(name : "URL" , value : "http://support.avaya.com/css/P8/documents/100124923");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed BIND version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("dns_server.nasl","bind_version.nasl");
 script_require_ports("Services/dns", 53);
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

if(!get_kb_item("DNS/tcp/53"))exit(0);
if(!version = get_kb_item("bind/version"))exit(0);
version = str_replace(find:"-", string: version, replace:".");

if(version_in_range(version:version,test_version:"9.6.2",test_version2:"9.6.2.P1") ||
   version_in_range(version:version,test_version:"9.6.ESV",test_version2:"9.6.ESV.R1") ||
   version_in_range(version:version,test_version:"9.7",test_version2:"9.7.2.P2")) {
      security_hole(port:53, proto:"udp");
      exit(0);
}  

exit(0);
