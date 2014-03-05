###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powerdns_51355.nasl 12 2013-10-27 11:15:33Z jan $
#
# PowerDNS Authoritative Server Remote Denial of Service Vulnerability
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
tag_summary = "PowerDNS is prone to a remote denial-of-service vulnerability.

Successfully exploiting this issue will allow attackers to cause the
application to fall into an endless packet loop with other DNS
servers, denying service to legitimate users.";

tag_solution = "The vendor has released a patch. Please see the references for
details.";

if (description)
{
 script_id(103383);
 script_bugtraq_id(51355);
 script_cve_id("CVE-2012-0206");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version("$Revision: 12 $");

 script_name("PowerDNS Authoritative Server Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51355");
 script_xref(name : "URL" , value : "http://wiki.powerdns.com/trac/changeset/2331");
 script_xref(name : "URL" , value : "http://www.powerdns.com/");
 script_xref(name : "URL" , value : "http://mailman.powerdns.com/pipermail/pdns-users/2012-January/008457.html");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-01-11 10:33:14 +0100 (Wed, 11 Jan 2012)");
 script_description(desc);
 script_summary("Determine if installed PowerDNS version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("pdns_version.nasl");
 script_require_udp_ports(53);
 script_require_keys("powerdns/version");
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

bindVer = get_kb_item("powerdns/version");
if(!bindVer){
    exit(0);
}

if("Recursor" >!< bindVer)exit(0);

version = eregmatch(pattern:"([0-9.]+)", string: bindVer);
if(isnull(version[1]))exit(0);

if(version_is_equal(version:version[1],test_version:"2.9.22.5"))exit(0); # according to http://mailman.powerdns.com/pipermail/pdns-users/2012-January/008457.html  2.9.22.5 is NOT affected.

if(version_is_less(version:version[1], test_version:"3.0.1") ) {
    security_warning(port:udpPort, proto:"udp");
    exit(0);
}

exit(0);

