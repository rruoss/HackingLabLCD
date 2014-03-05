###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_mult_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Flash Media Server Multiple Denial of Service Vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will let the remote unauthenticated attackers to
  run malicious code and crash the application resulting denial of service.
  Impact Level: Application";
tag_affected = "Flash Media Server 3.0.x before 3.0.7, 3.5.x before 3.5.5
  and 4.0.x before 4.0.1";
tag_insight = "The flaws are due to unspecified vectors. For more details please refer
  reference section.";
tag_solution = "Update to 4.0.1 or 3.5.5 or 3.0.7 and above.
  For updates refer to http://www.adobe.com/support/security/bulletins/apsb10-27.html";
tag_summary = "This host is running Adobe Flash Media Server and is prone to multiple
  denial of service vulnerabilities.";

if (description)
{
  script_id(800183);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-19 15:31:49 +0100 (Fri, 19 Nov 2010)");
  script_cve_id("CVE-2010-3633", "CVE-2010-3634", "CVE-2010-3635");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Flash Media Server Multiple Denial of Service Vulnerabilities");
 
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-27.html");

  script_description(desc);
  script_summary("Determine if Adobe Flash Media Server version is vulnerable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_require_ports("Services/www", 1111);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
mediaPort = get_http_port(default:1111);
if(!mediaPort){
    exit(0);
}

## Get Adobe Flash Media Server from KB's
fmsVer = get_kb_item("www/" + mediaPort + "/Adobe/FMS");
if(fmsVer == NULL){
    exit(0);
}

## Check for vulnerable versions <=4.0.0 or <=3.5.4 or <= 3.0.6
if(version_in_range(version:fmsVer, test_version:"4.0",  test_version2:"4.0.0")||
   version_in_range(version:fmsVer, test_version:"3.5",  test_version2:"3.5.4")||
   version_in_range(version:fmsVer, test_version:"3.0",  test_version2:"3.0.6")){
  security_hole(port:mediaPort);
}
