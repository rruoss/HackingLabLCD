###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_symantec_sygate_personal_firewall_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Symantec Sygate Personal Firewall ActiveX Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code on the system or cause the application to crash.
  Impact Level: Application/System";
tag_affected = "Symantec Sygate Personal Firewall 5.6 build 2808";
tag_insight = "The flaw is caused by an error in ActiveX control in SSHelper.dll
  allows remote attackers to execute arbitrary code via a long third
  argument to the SetRegString method.";
tag_solution = "No solution or patch is available as of 18th June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.symantec.com/norton/sygate/index.jsp";
tag_summary = "This host is installed with Symantec Sygate Personal Firewall and
  is prone to Buffer overflow vulnerability.";

if(description)
{
  script_id(901125);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-2305");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Symantec Sygate Personal Firewall ActiveX Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59408");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13834");
  script_xref(name : "URL" , value : "http://www.corelan.be:8800/index.php/forum/security-advisories/10-050-sygate-personal-firewall-5-6-build-2808-activex/");

  script_description(desc);
  script_summary("Check for the vulnerable version of Symantec Sygate Personal Firewall");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm Sygate Personal Firewall
if(!registry_key_exists(key:"SOFTWARE\Sygate Technologies, Inc." +
                              "\Sygate Personal Firewall")){
    exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
    exit(0);
}


## Get Sygate Personal Firewall version from registry
foreach item(registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Sygate Personal Firewall" >< name)
  {
    ver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ver != NULL)
    {
      if(version_is_equal(version:ver, test_version:"5.6.2808")){
        security_hole(0);
        exit(0);
      }
    }
  }
}
