###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_su11-003.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mac OS X v10.6.7 Multiple Vulnerabilities (2011-003)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions or cause a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "File Quarantine and Malware removal.";
tag_insight = "For more information on the vulnerabilities refer to the links below.";
tag_solution = "Run Mac Updates and update the Security Update 2011-003
  For updates refer to http://support.apple.com/kb/HT1222";
tag_summary = "This host is missing an important security update according to
  Mac OS X 10.6.7 Update/Mac OS X Security Update 2011-003.";

if(description)
{
  script_id(902467);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-25 09:25:35 +0200 (Thu, 25 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mac OS X v10.6.7 Multiple Vulnerabilities (2011-003)");
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
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT3662");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4651");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT1222");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2011//May/msg00000.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 SecPod");
  script_summary("Checks for existence of Mac OS X 10.6.7 Update/Mac OS X Security Update 2011-003");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/osx_name","ssh/login/osx_version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("pkg-lib-macosx.inc");
include("version_func.inc");

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
 exit(0);
}

## Check for the Mac OS X and Mac OS X Server
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_is_less_equal(version:osVer, test_version:"10.6.7"))
  {
    ## Check for the security update 2011.003
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2011.003"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
