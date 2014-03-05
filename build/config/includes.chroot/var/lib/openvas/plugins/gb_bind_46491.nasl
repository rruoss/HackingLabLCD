###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_46491.nasl 13 2013-10-27 12:16:33Z jan $
#
# ISC BIND 9 IXFR Transfer/DDNS Update Remote Denial of Service Vulnerability
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
tag_summary = "ISC BIND is prone to a remote denial-of-service vulnerability.

An attacker can exploit this issue to cause the affected service to
stop processing requests, denying service to legitimate users.

BIND versions 9.7.1 and 9.7.2 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103090);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-02-23 13:14:43 +0100 (Wed, 23 Feb 2011)");
 script_bugtraq_id(46491);
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2011-0414");

 script_name("ISC BIND 9 IXFR Transfer/DDNS Update Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46491");
 script_xref(name : "URL" , value : "http://www.isc.org/products/BIND/");
 script_xref(name : "URL" , value : "http://www.isc.org/software/bind/advisories/cve-2011-0414");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/559980");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Bind version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("dns_server.nasl","bind_version.nasl");
 script_require_ports("Services/dns", 53);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

if(!get_kb_item("DNS/tcp/53"))exit(0);
if(!version = get_kb_item("bind/version"))exit(0);
version = str_replace(find:"-", string: version, replace:".");

if(version_in_range(version:version,test_version:"9.7.1",test_version2:"9.7.2.P3")) {
  security_hole(port:53, proto:"udp");
  exit(0);
}

exit(0);

