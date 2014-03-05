###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drivecrypt_ioctl_priv_esc_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# SecurStar DriveCrypt 'DCR.sys' IOCTL Handling Privilege Escalation Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code.
  Impact Level: Application.";
tag_affected = "SecurStar DriveCrypt version 5.3 and 5.4";

tag_insight = "The flaw exists due to an error in the 'DCR.sys' driver when processing 'IOCTLs'
  and can be exploited to corrupt memory via a specially crafted 0x00073800 IOCTL.";
tag_solution = "Upgrade to SecurStar DriveCrypt version 5.5 or later
  For updates refer to http://www.securstar.com/downloads.php";
tag_summary = "This host is installed with SecurStar DriveCrypt and is prone to
  privilege escalation vulnerability.";

if(description)
{
  script_id(801799);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-0513");
  script_bugtraq_id(45750);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("SecurStar DriveCrypt 'DCR.sys' IOCTL Handling Privilege Escalation Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/70426");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42881");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15972/");

  script_description(desc);
  script_summary("Check for the version of DriveCrypt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  drvName = registry_get_sz(key:key + item, item:"DisplayName");
  if("DriveCrypt" >< drvName)
  {
    ## Get the version from registry
    drvVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(drvVer != NULL)
    {
      ## Check for DriveCrypt version equal to 5.3 or 5.4
      if(version_is_equal(version:drvVer, test_version:"5.3") ||
         version_is_equal(version:drvVer, test_version:"5.4")){
        security_hole(0) ;
      }
    }
  }
}
