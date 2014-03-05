###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_fraudulent_digital_cert_spoofing_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Fraudulent Digital Certificates Spoofing Vulnerability (2524375)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to spoof content, perform
  phishing attacks or perform man-in-the-middle attacks against all Web browser
  users including users of Internet Explorer.
  Impact Level: System.";
tag_affected = "Windows 7 Service Pack 1 and prior
  Windows XP Service Pack 3 and prior
  Windows Vista Service Pack 2 and prior
  Windows Server 2003 Service Pack 2 and prior
  Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is due to an error when handling the fraudulent digital
  certificates issued by Comodo and it is not properly validating its
  identity.";
tag_solution = "
This NVT has been superseded by KB2641690 Which is addressed in NVT
gb_ms_fraudulent_digital_cert_spoofing_vuln.nasl (OID:1.3.6.1.4.1.25623.1.0.802403)

Apply the Patch from below link,
  For updates refer to http://support.microsoft.com/kb/2524375";
tag_summary = "The host is installed with Microsoft Windows operating system and is prone
  to spoofing vulnerability.";

if(description)
{
  script_id(801953);
  script_version("$Revision: 13 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Fraudulent Digital Certificates Spoofing Vulnerability (2524375)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2524375");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/2524375.mspx");

  script_description(desc);
  script_summary("Check for the Microsoft Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

exit(66); ## This NVT is deprecated asit is superseded by KB2641690
          ## Which is addressed in gb_ms_fraudulent_digital_cert_spoofing_vuln.nasl

include("smb_nt.inc");
include("secpod_reg.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## Check Hotfix 2524375
if(!(hotfix_missing(name:"2524375") == 0)){
  security_warning(0);
}
