###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rosoft_audio_converter_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Rosoft Audio Converter '.M3U' file Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  on the system or cause the application to crash.
  Impact Level: Application.";
tag_affected = "Rosoft Audio Converter version 4.4.4";

tag_insight = "The flaw exists due to boundary error when processing '.M3U' file, which can
  be exploited by tricking a user into loading a specially crafted M3U file.";
tag_solution = "No solution or patch is available as of 22th June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.rosoftengineering.com/FreePrograms.aspx";
tag_summary = "This host is installed with Rosoft Audio Converter and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(902079);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-2329");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Rosoft Audio Converter '.M3U' file Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40195");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59483");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13895/");

  script_description(desc);
  script_summary("Check for the version of Rosoft Audio Converter");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_rosoft_audio_converter_detect.nasl");
  script_require_keys("Rosoft/Audio/Converter/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

## Get version from KB
racVer = get_kb_item("Rosoft/Audio/Converter/Ver");

if(racVer != NULL)
{
  ## Check Rosoft Audio Converter version equal to '4.4.4'
  if(version_is_equal(version:racVer, test_version:"4.4.4")){
    security_hole(0);
  }
}
