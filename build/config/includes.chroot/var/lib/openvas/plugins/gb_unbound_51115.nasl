###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unbound_51115.nasl 13 2013-10-27 12:16:33Z jan $
#
# Unbound Multiple Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "Unbound is prone to multiple remote denial-of-service vulnerabilities.

An attacker can exploit these issues to cause the affected application
to crash, denying service to legitimate users.

Versions prior to Unbound 1.4.14 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more details.";

if (description)
{
 script_id(103370);
 script_bugtraq_id(51115);
 script_cve_id("CVE-2011-4528", "CVE-2011-4869");
 script_version ("$Revision: 13 $");

 script_name("Unbound Multiple Denial of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://secunia.com/advisories/47220");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/209659");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51115");
 script_xref(name : "URL" , value : "http://unbound.nlnetlabs.nl/downloads/CVE-2011-4528.txt");
 script_xref(name : "URL" , value : "http://unbound.net/index.html");

 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-12-20 11:19:55 +0100 (Tue, 20 Dec 2011)");
 script_description(desc);
 script_summary("Determine if installed Unbound version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("unbound_version.nasl");
 script_require_udp_ports(53);
 script_require_keys("unbound/version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

udpPort = 53;
if(!get_udp_port_state(udpPort)){
    exit(0);
}

bindVer = get_kb_item("unbound/version");
if(!bindVer){
    exit(0);
}

if(version_is_less(version:bindVer, test_version:"1.4.14") ) {
    security_hole(port:udpPort, proto:"udp");
    exit(0);
}

exit(0);

