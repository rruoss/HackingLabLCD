###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_virusblokada_av_dos_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# VirusBlokAda Personal AV Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attacker to execute arbitrary codes
  through compressed rar achive and can cause memory corruption or service
  crash.";
tag_affected = "VirusBlokAda version 3.12.8.5 or prior.";
tag_insight = "Scanning archive files that are crafted maliciously causes application crash.";
tag_solution = "No solution or patch is available as of 22nd December, 2008. Information
  regarding this issue will be updated once the solution details are available.
  For further updates refer, http://www.anti-virus.by/en/personal.html";
tag_summary = "This host is installed with VirusBlokAda and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_id(800213);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-23 15:23:02 +0100 (Tue, 23 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5667");
  script_bugtraq_id(31560);
  script_name("VirusBlokAda Personal AV Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6658");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-5667");

  script_description(desc);
  script_summary("Check for the version of VirusBlokAda");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

vbacheck = registry_key_exists(key:"SOFTWARE\Vba32\Loader");
if(!vbacheck){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  vba = registry_get_sz(key:key + item, item:"DisplayName");
  if("Vba32" >< vba)
  {
    vbaVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(vbaVer != NULL)
    {
      # Grep for version 3.12.8.5 or prior
      if(version_is_less_equal(version:vbaVer, test_version:"3.12.8.5")){
        security_warning(0);
      }
    }
    exit(0);
  }
}
