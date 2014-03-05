###############################################################################
# OpenVAS Vulnerability Test
# $Id: bind_37118.nasl 15 2013-10-27 12:49:54Z jan $
#
# ISC BIND 9 DNSSEC Query Response Additional Section Remote Cache Poisoning Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "ISC BIND 9 is prone to a remote cache-poisoning vulnerability.

An attacker may leverage this issue to manipulate cache data,
potentially facilitating man-in-the-middle, site-impersonation, or denial-of-
service attacks.

Versions prior to the following are vulnerable:

BIND 9.4.3-P4 BIND 9.5.2-P1 BIND 9.6.1-P2";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100362);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-25 11:49:08 +0100 (Wed, 25 Nov 2009)");
 script_bugtraq_id(37118);
 script_cve_id("CVE-2009-4022");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("ISC BIND 9 DNSSEC Query Response Additional Section Remote Cache Poisoning Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37118");
 script_xref(name : "URL" , value : "https://www.isc.org/node/504");
 script_xref(name : "URL" , value : "http://www.isc.org/products/BIND/");

 script_description(desc);
 script_summary("Determine if BIND 9 is prone to a remote cache-poisoning vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("dns_server.nasl","bind_version.nasl");
 script_require_ports("Services/dns", 53);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

if(!get_kb_item("DNS/tcp/53"))exit(0);
if(!version = get_kb_item("bind/version"))exit(0);
version = str_replace(find:"-", string: version, replace:".");

if(version =~ "9\.[0-4]+") { 
  if(version_is_less(version: version, test_version: "9.4.3.P4")) {
    VULN = TRUE;
  } 
}
else if(version =~ "9\.5") {
  if(version_is_less(version: version, test_version: "9.5.2.P1")) {
    VULN = TRUE;
  }
}
else if(version =~ "9\.6") {
  if(version_is_less(version: version, test_version: "9.6.1.P2")) {
    VULN = TRUE;
  }
}

if(VULN) {
  security_warning(port:53, proto:"udp");
  exit(0);   
}
  
exit(0);
