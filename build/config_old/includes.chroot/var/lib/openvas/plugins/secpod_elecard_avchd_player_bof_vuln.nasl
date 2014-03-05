###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_elecard_avchd_player_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Elecard AVC HD  Player Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
# #
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
tag_impact = "Successful exploitation will allows attacker to execute arbitrary code
  in the context of the affected application.
  Impact Level: Application";
tag_affected = "Elecard AVC HD Player 5.5.90213 and prior on Windows.";
tag_insight = "Application fails to perform adequate boundary checks on user-supplied input
  which results in a buffer overflow while processing playlist(.xpl) containing
  long MP3 filenames.";
tag_solution = "Upgrade to Elecard AVC HD Player version 5.6.90515 or later
  For updates refer to http://www.elecard.com/download/index.php";
tag_summary = "This host is installed Elecard AVC HD Player and is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_id(900627);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1356");
  script_bugtraq_id(34560);
  script_name("Elecard AVC HD  Player Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8452");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/378145.php");

  script_description(desc);
  script_summary("Check for the version of Elecard AVC HD Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_elecard_avchd_player_detect.nasl");
  script_require_keys("Elecard/AVC/HD/Ver");
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

avcPlayer = get_kb_item("Elecard/AVC/HD/Ver");
if(!avcPlayer){
  exit(0);
}

if(version_is_less_equal(version:avcPlayer, test_version:"5.5.90213")){
  security_hole(0);
}
