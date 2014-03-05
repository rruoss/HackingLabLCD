###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_42344.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Flash Media Server Multiple Remote Security Vulnerabilities
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
tag_summary = "Adobe Flash Media Server is prone to multiple remote security
vulnerabilities, including multiple denial-of-service vulnerabilities
and a remote code-execution vulnerability.

An attacker can exploit these issues to execute arbitrary code in the
context of the affected application or cause denial-of-service
conditions.

These issues affect Flash Media Server (FMS) versions prior to 3.5.4
and 3.0.6.";

tag_solution = "Vendor updates are available. Please see the referenced advisory for
more information.";

if (description)
{
 script_id(100754);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-11 13:11:12 +0200 (Wed, 11 Aug 2010)");
 script_bugtraq_id(42344);
 script_cve_id("CVE-2010-2218","CVE-2010-2217","CVE-2010-2219","CVE-2010-2220");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Adobe Flash Media Server Multiple Remote Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42344");
 script_xref(name : "URL" , value : "http://www.adobe.com/products/flashmediaserver/");
 script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-19.html");

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

if(version_in_range(version:fmsVer, test_version:"3.5",  test_version2:"3.5.3")||
   version_is_less(version:fmsVer,  test_version:"3.0.6")){
     security_hole(port:mediaPort);
     exit(0);
}

exit(0);
