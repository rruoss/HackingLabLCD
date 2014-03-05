###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lotus_domino_46233.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Lotus Domino Server 'diiop' Multiple Remote Code Execution Vulnerabilities
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
tag_summary = "IBM Lotus Domino server is prone to multiple remote code-execution
vulnerabilities because it fails to perform adequate boundary checks
on user-supplied input.

Successfully exploiting these issues may allow remote attackers to
execute arbitrary code in the context of the Lotus Domino server
process. Failed attacks will cause denial-of-service conditions.";


if (description)
{
 script_id(103066);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-02-08 13:20:01 +0100 (Tue, 08 Feb 2011)");
 script_bugtraq_id(46233);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("IBM Lotus Domino Server 'diiop' Multiple Remote Code Execution Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46233");
 script_xref(name : "URL" , value : "http://www-142.ibm.com/software/sw-lotus/products/product4.nsf/wdocs/dominohomepage");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-052/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-053/");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if IBM Lotus Domino version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_lotus_domino_detect.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

## Get Lotus Domino Version from KB
domVer = get_kb_item("Domino/Version");
domPort = get_kb_item("Domino/Port/");
if(!domVer || !domPort){
    exit(0);
}

domVer = ereg_replace(pattern:"FP", string:domVer, replace: ".FP");

if(version_is_less_equal(version:domVer, test_version:"8.5.2")) {
  security_hole(port:domPort);
  exit(0);
}  

exit(0);
