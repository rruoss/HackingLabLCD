###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unbound_38701.nasl 14 2013-10-27 12:33:37Z jan $
#
# Unbound 'sock_list' Structure Allocation Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

Successful exploits may allow an attacker to crash the affected
application, resulting in a denial-of-service condition. Given the
nature of this issue, attackers may also be able to run arbitrary
code, but this has not been confirmed.

Versions prior to Unbound 1.4.3 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100531);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2010-0969");
 script_bugtraq_id(38701);
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Unbound 'sock_list' Structure Allocation Remote Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38701");
 script_xref(name : "URL" , value : "http://www.unbound.net/pipermail/unbound-users/2010-March/001057.html");
 script_xref(name : "URL" , value : "http://unbound.net/index.html");

 script_description(desc);
 script_summary("Determine if Unbound version is < 1.4.3");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("unbound_version.nasl");
 script_require_keys("unbound/version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

udpPort = 53;
if(!get_udp_port_state(udpPort)){
    exit(0);
}

bindVer = get_kb_item("unbound/version");
if(!bindVer){
    exit(0);
}

if(version_is_less(version:bindVer, test_version:"1.4.3") ) {
  security_warning(port:udpPort, proto:"udp");
  exit(0);
}

exit(0);

