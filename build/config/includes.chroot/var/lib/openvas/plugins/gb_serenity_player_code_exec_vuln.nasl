###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serenity_player_code_exec_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Serenity/Mplay Audio Player Code Execution Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow local/remote attackers to trick the user
  to access the crafted m3u playlist file, execute the crafted shellcode into the
  context of the affected system memory registers to take control of the machine
  running the affected application.
  Impact Level: System";
tag_affected = "Serenity/Mplay Audio Player 3.2.3.0 and prior on Windows.";
tag_insight = "There exists a stack overflow vulnerability within the 'MplayInputFile()'
  function in 'src/plgui.c' that fails to sanitize user input while the user
  crafts his/her own malicious playlist 'm3u' file.";
tag_solution = "No solution or patch is available as of 07th February, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://malsmith.kyabram.biz/serenity";
tag_summary = "This host is installed with Serenity/Mplay Audio Player and is prone
  to code execution vulnerability.";

if(description)
{
  script_id(800729);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-4097");
  script_name("Serenity/Mplay Audio Player Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/product/27998");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0911-exploits/serenityaudio-overflow.txt");

  script_description(desc);
  script_summary("Check for the Version of Serenity/Mplay Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_serenity_player_detect.nasl");
  script_require_keys("Serenity/Audio/Player/Ver");
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

if(appVer  = get_kb_item("Serenity/Audio/Player/Ver"))
{
  if(version_is_less_equal(version:appVer, test_version:"3.2.3.0")){
    security_hole(0);
  }
}

else if(appVer2 = get_kb_item("Mplay/Audio/Player/Ver"))
{
  if(version_is_less_equal(version:appVer2, test_version:"3.2.3.0")){
    security_hole(0);
  }
}
