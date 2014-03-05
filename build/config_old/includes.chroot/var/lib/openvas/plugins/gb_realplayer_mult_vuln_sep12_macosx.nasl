###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_mult_vuln_sep12_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# RealNetworks RealPlayer Multiple Vulnerabilities - Sep12 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  on the system or cause the application to crash.
  Impact Level: System/Application";
tag_affected = "RealPlayer version 12.0.0.1701 and prior on Mac OS X";
tag_insight = "Multiple errors caused, when
  - Unpacking AAC stream
  - Decoding AAC SDK
  - Handling RealMedia files, which can be exploited to cause a buffer
    overflow.";
tag_solution = "Upgrade to RealPlayer version 12.0.1.1750 or later,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803031);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2407", "CVE-2012-2408", "CVE-2012-2409", "CVE-2012-2410",
                "CVE-2012-3234");
  script_bugtraq_id(55473);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-21 16:44:53 +0530 (Fri, 21 Sep 2012)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities - Sep12 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50580");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027510");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/09072012_player/en/");

  script_description(desc);
  script_summary("Check for the version of RealPlayer on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

#Variable Initialization
rpVer = "";

#Get Version
rpVer = get_kb_item("RealPlayer/MacOSX/Version");
if(!rpVer){
  exit(0);
}

## Check for Realplayer version less than 12.0.1.1750
if(version_is_less(version: rpVer, test_version:"12.0.1.1750")){
  security_hole(0);
}
