###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_code_exe_vuln_win_may10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Firefox Code Execution Vulnerability (Win) - May10
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let attackers to execute arbitrary JavaScript
  with chrome privileges via a javascript: URI in input to an extension.
  Impact Level: Application";
tag_affected = "Firefox version prior to 3.6 on Windows";
tag_insight = "The flaw is due to error in 'nsIScriptableUnescapeHTML.parseFragment'
  method which does not properly sanitize 'HREF' attribute of an 'A' element
  or the 'ACTION' attribute of a 'FORM' element.";
tag_solution = "Upgrade to  Firefox version prior to 3.6.3 or later,
  For updates refer tohttp://www.mozilla.com/en-US/";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone
  to code execution vulnerability";

if(description)
{
  script_id(801326);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-1585");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Firefox Code Execution Vulnerability (Win) - May10");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/510883/100/0/threaded");
  script_xref(name : "URL" , value : "http://wizzrss.blat.co.za/2009/11/17/so-much-for-nsiscriptableunescapehtmlparsefragment/");
  script_xref(name : "URL" , value : "http://www.security-assessment.com/files/whitepapers/Cross_Context_Scripting_with_Firefox.pdf");

  script_description(desc);
  script_summary("Check for the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
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

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less_equal(version:ffVer, test_version:"3.6")){
  security_hole(0);
}
