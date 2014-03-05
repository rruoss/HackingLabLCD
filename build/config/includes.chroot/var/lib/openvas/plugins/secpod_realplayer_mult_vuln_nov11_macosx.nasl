###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realplayer_mult_vuln_nov11_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# RealNetworks RealPlayer Multiple Vulnerabilities Nov - 11 (Mac OS X)
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code or
  cause a denial of service.
  Impact Level: Application";
tag_affected = "RealPlayer version prior to 12.0.0.1703 on Mac OS X";
tag_insight = "Multiple flaws are due to,
  - Unspecified errors in RV20, RV10, RV30, ATRC and AAC codec, allows
    attackers to execute arbitrary code via unspecified vectors.
  - An unspecified error related to RealVideo rendering can be exploited
    to corrupt memory.";
tag_solution = "Upgrade to RealPlayer version 12.0.0.1703 or later,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902761);
  script_version("$Revision: 13 $");
  script_bugtraq_id(50741);
  script_cve_id("CVE-2011-4253", "CVE-2011-4252", "CVE-2011-4250", "CVE-2011-4246",
                "CVE-2011-4245", "CVE-2011-4255", "CVE-2011-4256");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-29 13:01:59 +0530 (Tue, 29 Nov 2011)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities Nov - 11 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46963/");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/11182011_player/en/");

  script_description(desc);
  script_summary("Check for the version of RealPlayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_realplayer_detect_macosx.nasl");
  script_require_keys("RealPlayer/MacOSX/Version");
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

rpVer = get_kb_item("RealPlayer/MacOSX/Version");
if(isnull(rpVer)){
  exit(0);
}

## Check for Realplayer version
if(version_is_less(version:rpVer, test_version:"12.0.0.1703")){
  security_hole(0);
}
