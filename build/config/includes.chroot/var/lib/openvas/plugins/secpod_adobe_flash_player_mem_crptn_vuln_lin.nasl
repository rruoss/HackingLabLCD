###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_flash_player_mem_crptn_vuln_lin.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Flash Player Remote Memory Corruption Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service.
  Impact Level: Application/System";
tag_affected = "Adobe Flash Player version 10.2.152.33 and prior on Linux.";
tag_insight = "The flaw is due to an error when handling the 'SWF' file, which allows
  attackers to execute arbitrary code or cause a denial of service via crafted
  flash content.";
tag_solution = "Upgrade to Adobe Flash Player version 10.2.153.1 or later.
  For details refer, http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  memory corruption vulnerability.";

if(description)
{
  script_id(902401);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_cve_id("CVE-2011-0609");
  script_bugtraq_id(46860);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Flash Player Remote Memory Corruption Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-06.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa11-01.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_require_keys("AdobeFlashPlayer/Linux/Ver");
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

flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!flashVer){
  exit(0);
}

flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");

## Check for Adobe Flash Player versions 10.2.152.33 and prior.
if(version_is_less_equal(version:flashVer, test_version:"10.2.152.33")){
  security_hole(0);
}
