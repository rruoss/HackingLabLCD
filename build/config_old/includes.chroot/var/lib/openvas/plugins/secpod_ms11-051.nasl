###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-051.nasl 13 2013-10-27 12:16:33Z jan $
#
# Active Directory Certificate Services Web Enrollment Elevation of Privilege Vulnerability (2518295)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Active Directory Certificate Services,
    - Microsoft Windows 2K3 Service Pack 2 and prior
    - Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is caused by improper input validation of a request parameter on an
  Active Directory Certificate Services Web Enrollment site.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS11-051.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-051.";

if(description)
{
  script_id(900289);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_bugtraq_id(48175);
  script_cve_id("CVE-2011-1264");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Active Directory Certificate Services Web Enrollment Elevation of Privilege Vulnerability (2518295)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2518295");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS11-051.mspx");

  script_description(desc);
  script_summary("Check for Registry Entry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
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
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2008:3) <= 0){
  exit(0);
}

## Confirm Active Directory Certificate Services Web Enrollment is installed
if(registry_key_exists(key:"SOFTWARE\Classes\AppID\certsrv.exe") &&
   registry_key_exists(key:"SOFTWARE\Classes\CertificateAuthority.DB"))
{
  ## MS11-051 Hotfix (2518295)
  if(hotfix_missing(name:"2518295") == 1){
    security_warning(0);
  }
}
