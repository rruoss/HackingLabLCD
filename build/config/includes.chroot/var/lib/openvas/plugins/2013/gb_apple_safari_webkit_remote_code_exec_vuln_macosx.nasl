###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webkit_remote_code_exec_vuln_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# Apple Safari Webkit Remote Code Execution Vulnerability - May13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the attackers to execute arbitrary code via
  crafted SVG document.
  Impact Level: System/Application";

tag_affected = "Apple Safari versions prior to 6.0.4 on Mac OS X";
tag_insight = "WebKit contains a type confusion flaw in the 'SVGViewSpec::viewTarget'
  function in WebCore/svg/SVGViewSpec.cpp when handling non-SVG elements.";
tag_solution = "Upgrade to Apple Safari version 6.0.4 or later,
  For updates refer to http://www.apple.com/support/downloads";
tag_summary = "The host is installed with Apple Safari web browser and is prone
  to remote code execution vulnerability.";

if(description)
{
  script_id(803604);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0912");
  script_bugtraq_id(58388);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-27 18:02:13 +0530 (Mon, 27 May 2013)");
  script_name("Apple Safari Webkit Remote Code Execution Vulnerability - May13 (Mac OS X)");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/91220");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5701");
  script_xref(name : "URL" , value : "http://prod.lists.apple.com/archives/security-announce/2013/Apr/msg00000.html");
  script_summary("Check for the vulnerable version of Apple Safari on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
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

## Variable Initialization
osName = "";
osVer = "";
safVer = "";

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
if("Mac OS X" >< osName)
{
  ## Check the affected OS versions
  if(version_is_equal(version:osVer, test_version:"10.7.5")||
     version_is_equal(version:osVer, test_version:"10.8.3"))
  {
    ## Get version from KB
    safVer = get_kb_item("AppleSafari/MacOSX/Version");
    if(!safVer){
      exit(0);
    }

    ## Grep for Apple Safari Versions prior to 6.0.4
    if(version_is_less(version:safVer, test_version:"6.0.4"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
