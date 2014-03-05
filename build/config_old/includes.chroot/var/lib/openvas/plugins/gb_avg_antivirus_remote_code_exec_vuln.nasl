###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avg_antivirus_remote_code_exec_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# AVG Anti-Virus 'hcp://' Protocol Handler Remote Code Execution Vulnerability
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
tag_solution = "No solution or patch is available as of 1st October, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.avg.com/in-en/download-trial

  NOTE: The researcher indicates that a vendor response was received, stating
  that 'AVG AVG9 and the new AVG2011 versions and both block this exploit on
  the network link layer using a linkscanner' but linkscanners can be beaten
  with obfuscation. Still does not address the flaw in the AV scanning engine";

tag_impact = "Successful exploitation could allow the attackers to bypass virus scanning
  and allows an attacker to drop and execute known malicious files.
  Impact Level: Application";
tag_affected = "AVG Anti-Virus versions 8.0, 8.0.156 and 8.0.323";
tag_insight = "The flaw is due to an error in application when interacting with the
  hcp:// URLs by the Microsoft Help and Support Center.";
tag_summary = "The host is installed with AVG Anti-Virus and is prone to remote
  code execution vulnerability.";

if(description)
{
  script_id(802976);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2010-3498");
  script_bugtraq_id(44189);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-01 18:51:18 +0530 (Mon, 01 Oct 2012)");
  script_name("AVG Anti-Virus 'hcp://' Protocol Handler Remote Code Execution Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.n00bz.net/antivirus-cve");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/514356");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2010/Jun/205");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check the version of AVG Anti-Virus");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_avg_detect_win.nasl");
  script_require_keys("AVG/AV/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

## Variable Initialization
avVer = "";

## Get the version from KB
avVer = get_kb_item("AVG/AV/Win/Ver");
if(!avVer){
  exit(0);
}

## Check for AVG Anti-Virus 2013 and prior
if(version_is_equal(version:avVer, test_version:"8.0") ||
   version_is_equal(version:avVer, test_version:"8.5.323") ||
   version_is_equal(version:avVer, test_version:"8.0.156")){
  security_hole(0);
}
