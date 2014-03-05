###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_xml_data_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Flash Media Server XML Data Remote Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "Adobe Flash Media Server version before 3.5.6, and 4.x before 4.0.2.";
tag_insight = "The flaw is due to an XML data corruption, leading to a denial of
  service.";
tag_solution = "Upgrade to Adobe Flash Media Server version 3.5.6, 4.0.2 or later,
  For updates refer to http://www.adobe.com/support/security/bulletins/apsb11-11.html";
tag_summary = "This host is running Adobe Flash Media Server and is prone to
  denial of service vulnerability.";

if (description)
{
  script_id(801892);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_bugtraq_id(47840);
  script_cve_id("CVE-2011-0612");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Adobe Flash Media Server XML Data Remote Denial of Service Vulnerability");

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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/1224");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-11.html");

  script_description(desc);
  script_summary("Determine if Adobe Flash Media Server version is vulnerable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Get Adobe Flash Media Server version from KB
fmsVer = get_kb_item("www/" + mediaPort + "/Adobe/FMS");
if(fmsVer == NULL){
  exit(0);
}

## Check for vulnerable versions
if(version_in_range(version:fmsVer, test_version:"4.0",  test_version2:"4.0.1")||
   version_is_less(version:fmsVer, test_version:"3.5.6")) {
  security_warning(port:mediaPort);
}
