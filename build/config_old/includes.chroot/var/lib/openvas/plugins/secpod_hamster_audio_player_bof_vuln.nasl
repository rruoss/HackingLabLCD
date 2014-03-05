###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hamster_audio_player_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Hamster Audio Player Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  Impact Level:System/Application";
tag_affected = "Hamster Audio Player 0.3a and prior on Windows.";
tag_insight = "This flaw is due to improper bounds checking when processing .m3u files
  and can be exploited by persuading a victim to open a specially-crafted
  .m3u or .hpl playlist file containing an overly long string.";
tag_solution = "No solution or patch is available as of th 22nd July, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer tohttp://www.ondanera.net/eng/download.html";
tag_summary = "This host is installed with Hamster Audio player and is prone
  to Stack Overflow Vulnerability.";

if(description)
{
  script_id(900693);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2550");
  script_name("Hamster Audio Player Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35825");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9172");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51732");
  
  script_description(desc);
  script_summary("Check for the Version of Hamster Audio Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_hamster_audio_player_detect.nasl");
  script_require_keys("Hamster/Audio-Player/Ver");
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

hamsterVer = get_kb_item("Hamster/Audio-Player/Ver");
if(hamsterVer != NULL)
{
  if(version_is_less_equal(version:hamsterVer, test_version:"0.3a")){
    security_hole(0);
  }
}
