###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webkit_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apple Safari 'webkit' Denial Of Service Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to crash the affected browser,
  resulting in a denial of service condition.
  Impact Level: Application";
tag_affected = "Apple Safari version (Safari.exe) 4.531.9.1";
tag_insight = "The flaw exist due to error in 'WebKit.dll' file in webkit when processing
  'JavaScript' that writes sequences in an infinite loop.";
tag_solution = "No solution or patch is available as of as on 10th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.apple.com/support/downloads";
tag_summary = "This host is installed with Apple Safari Web Browser and is prone to
  to Denial of Service vulnerabilities.";

if(description)
{
  script_id(801332);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1728");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Apple Safari 'webkit' Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/393589.php");
  script_xref(name : "URL" , value : "https://launchpad.net/bugs/cve/2010-1729");
  script_xref(name : "URL" , value : "http://security-tracker.debian.org/tracker/CVE-2010-1729");

  script_description(desc);
  script_summary("Check for the version of Apple Safari and WebKit.dll");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

function find_version(filepath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:filepath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:filepath);
  dllVer = GetVer(file:file, share:share);
  return dllVer;
}

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

key = "SOFTWARE\Apple Computer, Inc.\Safari";
asFile = registry_get_sz(item:"BrowserExe", key:key);
if(asFile)
{
  exeVer = find_version(filepath:asFile);
  if(!isnull(exeVer))
  {
    # Check for Safari.exe Version less or equal 4.31.9.1
    if(version_is_less_equal(version:exeVer, test_version:"4.31.9.1"))
    {
      dllVer = find_version(filepath:asFile - "\Safari\Safari.exe" +
                   "\Common Files\Apple\Apple Application Support\WebKit.dll");
      if(!isnull(dllVer))
      {
        # Check for WebKit.dll Version less or equal 4.31.9.1
         if(version_is_less_equal(version:dllVer, test_version:"4.31.9.1")){
           security_hole(0);
         }
      }
    }
  }
}
