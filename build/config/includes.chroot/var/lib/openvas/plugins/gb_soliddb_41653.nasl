###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_soliddb_41653.nasl 14 2013-10-27 12:33:37Z jan $
#
# IBM SolidDB 'solid.exe' Handshake Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
tag_summary = "IBM SolidDB is prone to a remote code-execution vulnerability.

An attacker can exploit this issue to execute arbitrary code with
SYSTEM user privileges. Failed exploit attempts will result in a denial-of-
service condition.

The vulnerability is reported in version 6.5 FP1 (6.5.0.1). Prior
versions may also be affected.";

tag_solution = "The vendor released updates to address this issue. Please see the
references for more information.";

if (description)
{
 script_id(100722);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-21 19:56:46 +0200 (Wed, 21 Jul 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2771");
 script_bugtraq_id(41653);

 script_name("IBM SolidDB 'solid.exe' Handshake Remote Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41653");
 script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21439148");
 script_xref(name : "URL" , value : "http://www.solidtech.com/en/products/relationaldatabasemanagementsoftware/embed.asp");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-125/");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed IBM SolidDB version is vulnerable.");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_ibm_soliddb_detect.nasl");
 script_require_ports("Services/soliddb", 1315);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/soliddb");
if(!port)port=1315;

if(!get_port_state(port))exit(0);

if(!v = get_kb_item(string("soliddb/",port,"/version")))exit(0);

if("Build" >< v) {
  version = eregmatch(pattern:"^[^ ]+", string:v);
  version = version[0];
} else {
  version = v;
}  

if(version_is_equal(version:version, test_version:"6.5.0.1")) {
  security_hole(port:port);
  exit(0);
}  
