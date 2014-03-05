###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dnsmasq_54353.nasl 12 2013-10-27 11:15:33Z jan $
#
# Dnsmasq Remote Denial of Service Vulnerability
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
tag_summary = "Dnsmasq is prone to a denial-of-service vulnerability.

An attacker can exploit this issue to cause denial-of-service
conditions through a stream of spoofed DNS queries producing
large results.

Dnsmasq versions 2.62 and prior are vulnerable.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103509";
CPE = "cpe:/a:thekelleys:dnsmasq";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54353);
 script_version ("$Revision: 12 $");
 
 script_name("Dnsmasq Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54353");
 script_xref(name : "URL" , value : "http://www.thekelleys.org.uk/dnsmasq/doc.html");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=833033");

 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-07-11 11:18:48 +0200 (Wed, 11 Jul 2012)");
 script_description(desc);
 script_summary("Determine if installed version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("dnsmasq_version.nasl");
 script_require_keys("dnsmasq/version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!dnsPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_udp_port_state(dnsPort)){
   exit(0);
}

if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:dnsPort))exit(0);

if(version_is_less(version: version, test_version: "2.62")) {
  security_hole(port:dnsPort);
  exit(0);
}  

exit(0);
