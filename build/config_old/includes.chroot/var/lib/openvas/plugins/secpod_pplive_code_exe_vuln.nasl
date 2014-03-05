###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pplive_code_exe_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PPLive Multiple Argument Injection Vulnerabilities
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
tag_impact = "By persuading a victim to click on a specially-crafted URI, attackers can
  execute arbitrary script code by loading malicious files(dll) through the
  UNC share pathname in the LoadModule argument.
  Impact Level: Application";
tag_affected = "PPLive version 1.9.21 and prior on Windows.";
tag_insight = "Improper validation of user supplied input to the synacast://, Play://,
  pplsv://, and ppvod:// URI handlers via a UNC share pathname in the
  LoadModule argument leads to this injection attacks.";
tag_solution = "No solution or patch is available as of 01st April, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.pplive.com/en/index.html";
tag_summary = "This host has PPLive installed and is prone to multiple argument
  injection vulnerabilities.";

if(description)
{
  script_id(900536);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1087");
  script_bugtraq_id(34128);
  script_name("PPLive Multiple Argument Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34327");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8215");

  script_description(desc);
  script_summary("Check for the Version of PPLive");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_pplive_detect.nasl");
  script_require_keys("PPLive/Ver");
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

ppliveVer = get_kb_item("PPLive/Ver");
if(!ppliveVer){
  exit(0);
}

# Check for PPLive version 1.9.21 and prior
if(version_is_less_equal(version:ppliveVer, test_version:"1.9.21")){
  security_hole(0);
}
