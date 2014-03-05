###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_audition_ses_mult_bof_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Audition '.ses' Multiple Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  or cause a denial of service via crafted data in unspecified fields in
  the TRKM chunk in an Audition Session file.
  Impact Level: Application";
tag_affected = "Adobe Audition version 3.0.1 and earlier on Windows";
tag_insight = "The flaw is due to an error when handling '.SES' (session) format
  file, which results in memory corruption, application crash or possibly
  execute arbitrary code.";
tag_solution = "No solution or patch is available as of 26th May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/products/audition.html";
tag_summary = "The host is installed with Adobe Audition and is prone to multiple
  buffer overflow vulnerabilities.";

if(description)
{
  script_id(902373);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-0614", "CVE-2011-0615");
  script_bugtraq_id(47841, 47838);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Audition '.ses' Multiple Buffer Overflow Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17278/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-10.html");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5012.php");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/Adobe-Audition-malformed-SES-file");
  
  script_description(desc);
  script_copyright("Copyright (C) 2011 SecPod");
  script_summary("Check the version of Adobe Audition");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("Adobe/Audition/Win/Ver");
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
audVer = get_kb_item("Adobe/Audition/Win/Ver");
if(!audVer){
  exit(0);
}

## Check for Adobe Audition version <= 3.0.1
if(version_is_less_equal(version:audVer, test_version:"3.0.1")){
  security_hole(0);
}
