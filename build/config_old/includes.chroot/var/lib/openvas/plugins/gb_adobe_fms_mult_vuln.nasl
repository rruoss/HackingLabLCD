###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Flash Media Server multiple vulnerabilities.
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
tag_summary = "Adobe Flash Media Server is prone to a directory-traversal
vulnerability and to a remote denial-of-service vulnerability.

Exploiting the directory-traversal issue can allow an attacker to load
arbitrary Dynamic Linked Libraries (DLLs) present on the server. This
could help the attacker launch further attacks.

Successful exploits of the denial-of-service vulnerability will allow
attackers to consume an excessive amount of CPU resources, denying
service to legitimate users.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100551);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-25 19:45:44 +0100 (Thu, 25 Mar 2010)");
 script_bugtraq_id(37420,37419);
 script_cve_id("CVE-2009-3792","CVE-2009-3791");

 script_name("Adobe Flash Media Server multiple vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37420");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37419");
 script_xref(name : "URL" , value : "http://www.adobe.com/products/flashmediaserver/");
 script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-18.html");

 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if Adobe Flash Media Server version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_adobe_fms_detect.nasl");
 script_require_ports("Services/www", 1111);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

mediaPort = get_http_port(default:1111);
if(!mediaPort){
    exit(0);
}

fmsVer = get_kb_item("www/" + mediaPort + "/Adobe/FMS");
if(fmsVer == NULL){
    exit(0);
}

if(version_in_range(version:fmsVer, test_version:"3.5",  test_version2:"3.5.2")||
   version_is_less(version:fmsVer,  test_version:"3.0.5")){
     security_hole(port:mediaPort);
}
