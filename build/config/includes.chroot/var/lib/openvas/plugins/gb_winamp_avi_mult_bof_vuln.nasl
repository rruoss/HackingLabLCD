###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winamp_avi_mult_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Winamp 'AVI' File Multiple Heap-based Buffer Overflow Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in the
  context of the application.
  Impact Level: System/Application";
tag_affected = "Winamp version before 5.63 build 3235";

tag_insight = "Errors in bmp.w5s,
  - when allocating memory using values from the 'strf' chunk to process BI_RGB
    video and UYVY video data within AVI files.
  - when processing decompressed TechSmith Screen Capture Codec (TSCC) data
    within AVI files.";
tag_solution = "upgrade to Winamp 5.63 build 3235 or later,
  For updates refer to http://www.winamp.com/media-player";
tag_summary = "This host is installed with Winamp and is prone to heap-based
  buffer overflow vulnerabilities.";

if(description)
{
  script_id(802926);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4045");
  script_bugtraq_id(54131);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-02 18:57:35 +0530 (Thu, 02 Aug 2012)");
  script_name("Winamp 'AVI' File Multiple Heap-based Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/83097");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46624");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54131/discuss");
  script_xref(name : "URL" , value : "http://forums.winamp.com/showthread.php?t=345684");

  script_description(desc);
  script_summary("Check for the version of Winamp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_require_keys("Winamp/Version");
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

## Variable Initialization
winampVer = "";

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

# Check for version less than 5.63 build 3235(5.6.3.3235)
if(version_is_less(version:winampVer, test_version:"5.6.3.3235")){
  security_hole(0);
}
