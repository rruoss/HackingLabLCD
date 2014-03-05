###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_mult_vuln_nov11_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Flash Player/Air Multiple Vulnerabilities - November 11 (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_solution = "Update to Adobe Air version 3.1.0.4880 or later
  For updates refer to http://get.adobe.com/air

  Update to Adobe Flash Player version 10.3.183.11 or 11.1.102.55 or later
  For updates refer to http://get.adobe.com/flashplayer/";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via unspecified
  vectors.
  Impact Level: Application/System";
tag_affected = "Adobe AIR version prior to 3.1.0.4880 on MAC OS X
  Adobe Flash Player version prior to 10.3.183.11 and 11.x through 11.0.1.152 on MAC OS X";
tag_insight = "The flaws are due to memory corruption, heap corruption, buffer
  overflow, stack overflow errors that could lead to code execution.";
tag_summary = "This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(902751);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-2445", "CVE-2011-2450", "CVE-2011-2451", "CVE-2011-2452",
                "CVE-2011-2453", "CVE-2011-2454", "CVE-2011-2455", "CVE-2011-2456",
                "CVE-2011-2457", "CVE-2011-2458", "CVE-2011-2459", "CVE-2011-2460");
  script_bugtraq_id(50625, 50619, 50623, 50622, 50618, 50626, 50627, 50624,
                    50621, 50629, 50620, 50628);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-16 11:54:43 +0530 (Wed, 16 Nov 2011)");
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities - November 11 (MAC OS X)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/46818/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-28.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player/Air");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_require_keys("Adobe/Flash/Player/MacOSX/Version",
                      "Adobe/Air/MacOSX/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

# Check for Adobe Flash Player
playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(playerVer != NULL)
{
  # Grep for version < 10.3.183.11 or 11.x through 11.0.1.152
  if(version_is_less(version:playerVer, test_version:"10.3.183.11") ||
    version_in_range(version:playerVer, test_version:"11.0", test_version2:"11.0.1.152"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Air
airVer = get_kb_item("Adobe/Air/MacOSX/Version");
if(airVer != NULL)
{
  # Grep for version < 3.1.0.4880
  if(version_is_less(version:airVer, test_version:"3.1.0.4880")){
    security_hole(0);
  }
}