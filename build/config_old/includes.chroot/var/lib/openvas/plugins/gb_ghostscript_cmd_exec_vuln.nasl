###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ghostscript_cmd_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ghostscript Arbitrary Command Execution Vulnerability.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows the attackers to execute arbitrary postscript
  commands via the 'gs_init.ps' file, if a user is tricked into opening a file
  using the '-P-' option in an attacker controlled directory.
  Impact Level: Application";
tag_affected = "Ghostscript version 8.71 and prior";
tag_insight = "The flaw is due to, application reading certain postscript files in
  the current working directory although the '-P-' command line option is set.";
tag_solution = "No solution or patch is available as of 23rd July, 2010. Information
  regddarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ghostscript.com/";
tag_summary = "This host is installed with Ghostscript and is prone to
  arbitrary command execution vulnerability.";

if(description)
{
  script_id(801412);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_cve_id("CVE-2010-2055");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ghostscript Arbitrary Command Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40452");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1757");

  script_description(desc);
  script_summary("Check for the Version of Ghostscript");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ghostscript_detect_win.nasl");
  script_require_keys("Ghostscript/Win/Ver");
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

## Get the version from KB
ghostVer = get_kb_item("Ghostscript/Win/Ver");
if(!ghostVer){
  exit(0);
}

## Check for the Ghostscript version <= 8.71
if(version_is_less_equal(version:ghostVer, test_version:"8.71")){
   security_hole(0);
}
