###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_9_7_2_P2.nasl 13 2013-10-27 12:16:33Z jan $
#
# ISC BIND 9 < 9.7.2-P2 Multiple Vulnerabilities
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
tag_summary = "ISC BIND is prone to multiple vulnerabilities.

1.
A remote denial-of-service vulnerability because
the software fails to handle certain bad signatures in a DNS query.

An attacker can exploit this issue to cause the application to crash,
denying service to legitimate users.

2. 
A security-bypass vulnerability.

Successfully exploiting this issue allows remote attackers to bypass
zone-and-view Access Control Lists (ACLs) to perform unintended
queries.

Versions prior to BIND 9.7.2-P2 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103031);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-14 14:24:22 +0100 (Fri, 14 Jan 2011)");
 script_bugtraq_id(45015,45385);
 script_cve_id("CVE-2010-4172","CVE-2010-3762");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("ISC BIND 9 < 9.7.2-P2 Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45385");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45015");
 script_xref(name : "URL" , value : "http://ftp.isc.org/isc/bind9/9.7.2-P2/RELEASE-NOTES-BIND-9.7.2-P2.html");
 script_xref(name : "URL" , value : "https://www.isc.org/software/bind/advisories/cve-2010-3615");
 script_xref(name : "URL" , value : "https://www.redhat.com/security/data/cve/CVE-2010-3762.html");
 script_xref(name : "URL" , value : "http://www.isc.org/products/BIND/");
 script_xref(name : "URL" , value : "http://support.avaya.com/css/P8/documents/100124923");

 script_tag(name:"risk_factor", value:"Medium");
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

if(version_in_range(version:version,test_version:"9.7",test_version2:"9.7.2.P1")) {
  security_warning(port:53, proto:"udp");
  exit(0);
}

exit(0);
