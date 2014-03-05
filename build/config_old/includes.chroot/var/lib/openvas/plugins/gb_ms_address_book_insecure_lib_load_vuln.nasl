###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_address_book_insecure_lib_load_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows Address Book Insecure Library Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to load arbitrary libraries by
  tricking a user into opening a vCard (.vcf).
  Impact Level: System";
tag_affected = "Microsoft Windows 7
  Microsoft Windows XP SP3 and prior.
  Microsoft Windows Vista SP 2 and prior.
  Microsoft Windows Server 2008 SP 2 and prior.
  Microsoft Windows Server 2003 SP 2 and prior.";
tag_insight = "The flaw is due to the way Microsoft Address Book loads libraries in an
  insecure manner.";
tag_solution = "No solution or patch is available as of 18th October, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/en/us/default.aspx";
tag_summary = "This host is installed with Microsoft Address Book and is prone to
  insecure library loading vulnerability.";

if(description)
{
  script_id(801457);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_cve_id("CVE-2010-3143");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Windows Address Book Insecure Library Loading Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14778/");
  script_xref(name : "URL" , value : "http://www.attackvector.org/new-dll-hijacking-exploits-many/");

  script_description(desc);
  script_summary("Check for the Windows Contacts Address Book Existence");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
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

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:1) <= 0){
 exit(0);
}

## Check the existance of Address Book for Win XP and Win 2003
key = "SOFTWARE\Clients\Contacts\Address Book";
if(registry_key_exists(key:key))
{
  key = "SOFTWARE\Microsoft\Active Setup\Installed Components\";
  if(registry_key_exists(key:key))
  {
  foreach item (registry_enum_keys(key:key))
  {
    addName = registry_get_sz(key:key + item, item:"ComponentID");
    if("WAB" >< addName)
    {
      addVer = registry_get_sz(key:key + item, item:"Version");
      if(addVer != NULL)
      {
        if(version_is_less_equal(version:addVer, test_version:"6.0.2900.5512"))
        {
          security_hole(0);
          exit(0);
        }
      }
    }
  }
  }
}

## Check the existance of the Windows Contacts for windows 7 and win vista
key = "SOFTWARE\Microsoft\Windows Mail\Advanced Settings\Contacts\";
if(!registry_key_exists(key:key)){
 exit(0);
}

winName = registry_get_sz(key:key, item:"Text");
if("Windows Contacts" >< winName){
  security_hole(0);
}
