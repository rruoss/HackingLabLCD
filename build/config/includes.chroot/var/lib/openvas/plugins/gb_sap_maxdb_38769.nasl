###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_maxdb_38769.nasl 14 2013-10-27 12:33:37Z jan $
#
# SAP MaxDB 'serv.exe' Unspecified Remote Code Execution Vulnerability
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
tag_summary = "SAP MaxDB is prone to an unspecified remote code-execution
vulnerability because it fails to sufficiently validate user-
supplied input.

An attacker can leverage this issue to execute arbitrary code with
SYSTEM-level privileges. Failed exploit attempts will result in a denial-of-
service condition.";

tag_solution = "Updates are available; please contact the vendor for more information.";

if (description)
{
 script_id(100541);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-17 21:52:47 +0100 (Wed, 17 Mar 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-1185");
 script_bugtraq_id(38769);
 script_tag(name:"risk_factor", value:"Critical");

 script_name("SAP MaxDB 'serv.exe' Unspecified Remote Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38769");
 script_xref(name : "URL" , value : "https://www.sdn.sap.com/irj/sdn/maxdb");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-032/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/510125");

 script_description(desc);
 script_summary("Determine if installed MaxDB version is vulnerable.");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_sap_maxdb_detect.nasl");
 script_require_ports("Services/unknown", 7210);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/unknown");
if(!port)port=7210;

if(!version = get_kb_item(string("sap_maxdb/", port, "/version")))exit(0);
if(!build   = get_kb_item(string("sap_maxdb/", port, "/build")))exit(0);
build = ereg_replace(pattern:"^([0-9]+)\-[0-9]+\-[0-9]+\-[0-9]+$",string:build,replace:"\1");

maxdb_version = string(version,".",build);

if(version_is_equal(version: maxdb_version, test_version: "7.6.6")     ||
   version_is_equal(version: maxdb_version, test_version: "7.6.3.007") ||
   version_is_equal(version: maxdb_version, test_version: "7.6.03.15") ||
   version_is_equal(version: maxdb_version, test_version: "7.6.00.37") ||
   version_is_equal(version: maxdb_version, test_version: "7.6.0.37")  ||
   version_is_equal(version: maxdb_version, test_version: "7.4.3.32")) {

     security_hole(port:port);
     exit(0);

}  
exit(0);

