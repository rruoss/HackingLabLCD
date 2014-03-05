###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_media_player_classic_midi_iof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Gabset Media Player Classic Integer Overflow Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation allows the attacker to execute arbitrary codes and may
  crash the player.
  Impact Level: Application";
tag_affected = "Gabset Media Player Classic 6.4.9 and prior on Windows.";
tag_insight = "An integer overflow occurs when processing specially crafted MIDI (.mid) files
  containg a malformed header.";
tag_solution = "No solution or patch is available as of 17th September, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/guliverkli/";
tag_summary = "This host is installed with Gabset Media Player Classic and is
  prone to Integer Overflow vulnerability.";

if(description)
{
  script_id(900948);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3201");
  script_bugtraq_id(36333);
  script_name("Gabset Media Player Classic Integer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/385461.php");

  script_description(desc);
  script_summary("Check for the version of Gabset Media Player Classic");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_media_player_classic_detect.nasl");
  script_require_keys("MediaPlayerClassic/Ver");
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

mpcVer = get_kb_item("MediaPlayerClassic/Ver");
if(!mpcVer) {
  exit(0);
}

if(version_is_less_equal(version:mpcVer, test_version:"6.4.9")){
  security_warning(0);
}
