###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_helix_47110.nasl 13 2013-10-27 12:16:33Z jan $
#
# RealNetworks Helix Server < 14.2 Multiple Vulnerabilities
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
tag_summary = "1. RealNetworks Helix Server is prone to a remote code-execution
vulnerability because of a format-string error.

Successful exploits can allow the attacker to execute arbitrary code
in the context of the application. Failed exploit attempts will result
in a denial-of-service condition.

2. RealNetworks Helix Server and Helix Mobile Server are prone to a
remote stack-based buffer-overflow vulnerability due to a failure to
properly bounds-check user-supplied data.

An attacker can exploit this issue to execute arbitrary code in the
context of the affected application. Failed exploit attempts will
result in a denial-of-service condition.";

tag_solution = "Updates are available. Please see the reference for more details.";

if (description)
{
 script_id(103137);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-04-01 13:32:12 +0200 (Fri, 01 Apr 2011)");
 script_bugtraq_id(47109,47110);
 script_cve_id("CVE-2010-4235","CVE-2010-4596");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("RealNetworks Helix Server < 14.2 Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47110");
 script_xref(name : "URL" , value : "http://www.realnetworks.com/products/media_delivery.html");
 script_xref(name : "URL" , value : "http://docs.real.com/docs/security/SecurityUpdate033111HS.pdf");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed Helix version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("rtsp_detect.nasl");
 script_require_ports("Services/rtsp", 554);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/rtsp");
if(!port)port = 554;
if(!get_port_state(port))exit(0);

if(!server = get_kb_item(string("RTSP/",port,"/Server")))exit(0);
if("Server: Helix" >!< server)exit(0);

version = eregmatch(pattern:"Version ([0-9.]+)", string: server);

if(isnull(version[1]))exit(0);

if(version_is_less(version:version[1], test_version:"14.2")) {
  security_hole(port:port);
  exit(0);
}  

exit(0);
