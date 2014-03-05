###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_vbscript_remote_code_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# MS Internet Explorer 'VBScript' Remote Code Execution Vulnerability (981169)
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
tag_solution = "No solution or patch is available as of th 05rd March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/downloads/default.aspx

  Workaround:
  Apply workaround as in the advisory.

  Referencea:
  http://securitytracker.com/alerts/2010/Mar/1023668.html
  http://www.microsoft.com/technet/security/advisory/981169.mspx
  http://isec.pl/vulnerabilities/isec-0027-msgbox-helpfile-ie.txt";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  via specially crafted attack.
  Impact Level: System";
tag_affected = "Microsoft Internet Explorer version 6.x, 7.x, 8.x";
tag_insight = "The flaw exists in the way that 'VBScript' interacts with Windows Help files
  when using Internet Explorer. If a malicious Web site displayed a specially
  crafted dialog box and a user pressed the F1 key, it allows arbitrary code
  to be executed in the security context of the currently logged-on user.";
tag_summary = "The host is installed with Internet Explorer and VBScript and is
  prone to Remote Code Execution vulnerability.";

if(description)
{
  script_id(800482);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0483");
  script_bugtraq_id(38463);
  script_name("MS Internet Explorer 'VBScript' Remote Code Execution Vulnerability");
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
  script_summary("Check for the version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

exit(0); ## Plugin may results to FP

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(ieVer =~ "^[6|7|8]\.*")
{
  exePath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(!exePath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:exePath + "\winhlp32.exe");
  dllVer = GetVer(file:file, share:share);
  if(!isnull(dllVer)){
    security_hole(0);
  }
}
