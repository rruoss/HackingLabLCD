###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tfm_mmplayer_m3u_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# TFM MM Player '.m3u' Buffer Overflow Vulnerability - July-09
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows the attacker to execute arbitrary code on
  the system or cause the application to crash.
  Impact Level: Application";
tag_affected = "TFM MMPlayer version 2.0 to 2.2.0.30 on Windows.";
tag_insight = "This flaw is due to improper bounds checking when processing '.m3u' files
  and can be exploited via crafted '.m3u' playlist file containing an overly
  long string.";
tag_solution = "No solution or patch is available as of th 24th July, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.tfm.ro/mmplayer/top.html";
tag_summary = "This host is installed with TFM MMPlayer and is prone to stack
  based Buffer Overflow bulnerability.";

if(description)
{
  script_id(900597);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2566");
  script_name("TFM MMPlayer '.m3u' Buffer Overflow Vulnerability - July-09");
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

  
  script_description(desc);
  script_summary("Check for the Version of TFM MMPlayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_tfm_mmplayer_detect.nasl");
  script_require_keys("TFM/MMPlayer/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35605");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9047");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51442");
  exit(0);
}


include("version_func.inc");

mmplayerVer = get_kb_item("TFM/MMPlayer/Ver");
if(mmplayerVer != NULL)
{
  # Grep for MMPlayer version 2.0 <= 2.2.0.30
  if(version_in_range(version:mmplayerVer, test_version:"2.0",
                                           test_version2:"2.2.0.30")){
    security_hole(0);
  }
}
