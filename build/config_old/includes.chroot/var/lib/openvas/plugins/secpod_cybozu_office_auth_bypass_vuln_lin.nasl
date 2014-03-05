###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cybozu_office_auth_bypass_vuln_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Cybozu Office Authentication Bypass Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to bypass authentication
  and obtain or modify sensitive information by using the unique ID of the
  'user&qts' cell phone.
  Impact Level: Application.";
tag_affected = "Cybozu Office version before 8 (8.1.0.1)";

tag_insight = "The flaw exists due to insufficient checks being performed when accessing
  the 'login' interface.";
tag_solution = "Cybozu Office 8 (8.1.0.1)
  For updates refer to http://products.cybozu.co.jp/office";
tag_summary = "This host is installed with Cybozu Office and is prone to
  authentication bypass vulnerability.";

if(description)
{
  script_id(902065);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2029");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("Cybozu Office Authentication Bypass Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39508");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57976");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN87730223/index.html");
  script_xref(name : "URL" , value : "http://www.ipa.go.jp/security/english/vuln/201004_cybozu_en.html");

  script_description(desc);
  script_summary("Check for the version of Cybozu Office");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Confirm Linux, as SSH can be instslled on Windows as well
result = ssh_cmd(socket:sock, cmd:"uname");
if("Linux" >!< result){
  exit(0);
}

cbofName = find_file(file_name:"sched", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:sock);

foreach binaryName (cbofName)
{
  binaryName = chomp(binaryName);

  ## Grep for the version
  cbofVer = get_bin_version(full_prog_name:binaryName, sock:sock,
                           version_argv:"--version",
                           ver_pattern:"Cybozu_Scheduling_Service ([0-9.]+)");
  
  ## Check for the Cybozu office version <= 8 (8.1.0.1)
  if(cbofVer[1] != NULL)
  {
    ## Check for the Cybozu office version <= 8 (8.1.0.1)
    if(version_is_less(version:cbofVer[1], test_version:"8.1.0.1")){
      security_hole(0);
    }
  }
}
ssh_close_connection();
