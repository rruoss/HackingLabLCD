###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_dreamweaver_insecure_lib_load_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Dreamweaver Insecure Library Loading Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code and conduct DLL hijacking attacks.
  Impact Level: Application";
tag_affected = "Adobe Dreamweaver CS5 11.0";
tag_insight = "This flaw is due to the application insecurely loading certain
  librairies from the current working directory, which could allow attackers
  to execute arbitrary code by tricking a user into opening a file from a
  network share.";
tag_solution = "No solution or patch is available as of 31st August, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Dreamweaver and is prone to
  Insecure Library Loading vulnerability.";

if(description)
{
  script_id(901149);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3132");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Dreamweaver Insecure Library Loading Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41110");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14740");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2171");

  script_description(desc);
  script_summary("Check for the version of Adobe Dreamweaver");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_dreamweaver_detect.nasl");
  script_require_keys("Adobe/Dreamweaver/Ver");
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

## Get version from KB
ver = get_kb_item("Adobe/Dreamweaver/Ver");
adobeVer = eregmatch(pattern:"^(.+) Adobe Dreamweaver (.*)$", string:ver);

if(!isnull(adobeVer[1]) && ( "CS5" >< adobeVer[2]))
{
  ##Grep for Adobe Dreamweaver CS5 Version 11.0
  if(version_is_equal(version:adobeVer[1], test_version:"11.0") ){
    security_hole(0);
  }
}
