###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_u3d_mem_crptn_vuln_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Reader/Acrobat 'U3D' Component Memory Corruption Vulnerability - Mac OS X
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the affected application or cause a denial of service.
  Impact Level: Application";
tag_affected = "Adobe Reader versions 9.x through 9.4.6 and 10.x through 10.1.1 on Mac OS X
  Adobe Acrobat versions 9.x through 9.4.6 and 10.x through 10.1.1 on Mac OS X";
tag_insight = "The flaw is due to an unspecified error while handling U3D data.";
tag_solution = "Upgrade to Adobe Reader version 9.4.7 or 10.1.2 or later,
  Upgrade to Adobe Acrobat version 9.4.7 or 10.1.2 or later,
  For updates refer to http://www.adobe.com/";
tag_summary = "This host is installed with Adobe Reader/Acrobat and is prone to
  memory corruption vulnerability.";

if(description)
{
  script_id(802543);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-2462", "CVE-2011-4369");
  script_bugtraq_id(50922, 51092);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-09 12:46:29 +0530 (Fri, 09 Dec 2011)");
  script_name("Adobe Reader/Acrobat 'U3D' Component Memory Corruption Vulnerability - Mac OS X");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47133/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa11-04.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-30.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_require_keys("Adobe/Reader/MacOSX/Version",
                      "Adobe/Acrobat/MacOSX/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Function to check the versions of abode reader and acrobat
function version_check(ver)
{
  if(version_in_range(version:ver, test_version:"9.0", test_version2:"9.4.6") ||
     version_in_range(version:ver, test_version:"10.0", test_version2:"10.1.1"))
  {
    security_hole(0);
    exit(0);
  }
}

## Get Reader Version
readerVer = get_kb_item("Adobe/Reader/MacOSX/Version");
if(readerVer){
  version_check(ver:readerVer);
}

## Get Acrobat version
acrobatVer = get_kb_item("Adobe/Acrobat/MacOSX/Version");
if(acrobatVer){
  version_check(ver:acrobatVer);
}
