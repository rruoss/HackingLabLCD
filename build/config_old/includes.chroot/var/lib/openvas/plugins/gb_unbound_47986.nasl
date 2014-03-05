###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unbound_47986.nasl 13 2013-10-27 12:16:33Z jan $
#
# Unbound DNS Resolver Remote Denial of Service Vulnerability
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
tag_summary = "Unbound is prone to a remote denial-of-service vulnerability.

Successfully exploiting this issue allows remote attackers to crash
the server, denying further service to legitimate users.

Versions prior to Unbound 1.4.10 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103170);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-06-03 14:27:02 +0200 (Fri, 03 Jun 2011)");
 script_bugtraq_id(47986);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-1922");

 script_name("Unbound DNS Resolver Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47986");
 script_xref(name : "URL" , value : "http://unbound.net/index.html");
 script_xref(name : "URL" , value : "http://unbound.nlnetlabs.nl/downloads/CVE-2011-1922.txt");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/531342");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed unbound version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("unbound_version.nasl");
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

if(version_is_less(version:bindVer, test_version:"1.4.10") ) {
  security_warning(port:udpPort, proto:"udp");
  exit(0);
}

exit(0);
