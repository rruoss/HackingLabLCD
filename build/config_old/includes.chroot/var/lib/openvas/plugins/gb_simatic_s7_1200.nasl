###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_s7_1200.nasl 12 2013-10-27 11:15:33Z jan $
#
# Siemens SIMATIC S7-1200 SSL Private Key Reuse Spoofing Vulnerability
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
tag_summary = "Siemens SIMATIC S7-1200 is prone to a security vulnerability that may
allow attackers to spoof SSL certificates.

Attackers can exploit this issue to display incorrect SSL
certificates. Successful exploits will cause victims to accept the
certificates assuming they are from a legitimate site.

Siemens SIMATIC S7-1200 versions 2.x are vulnerable; other versions
may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103571";
CPE = "cpe:/h:siemens:simatic_s7-1200_plc";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55559);
 script_cve_id("CVE-2012-3037");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 12 $");

 script_name("Siemens SIMATIC S7-1200 SSL Private Key Reuse Spoofing Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55559");
 script_xref(name : "URL" , value : "http://subscriber.communications.siemens.com/");
 script_xref(name : "URL" , value : "http://www.siemens.com/corporate-technology/pool/de/forschungsfelder/siemens_security_advisory_ssa-240718.pdf");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-09-20 10:18:56 +0200 (Thu, 20 Sep 2012)");
 script_description(desc);
 script_summary("Determine if SIMATIC S7-1200 FW version is 2.x");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_simatic_S7_1200_plc_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_udp_ports("Services/snmp", 161);
 script_require_keys("simatic_s7_1200/installed");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);

}

include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version =~ "^2\.") {

  security_hole(port:port);
  exit(0);

}  

exit(0);

