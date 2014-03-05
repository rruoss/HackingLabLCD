###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_norton_internet_sec_dos_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Norton Internet Security Denial of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to deny the service.
  Impact Level: Application";
tag_affected = "Symantec, Norton AntiVirus version 15.5.0.23 on Windows.";
tag_insight = "The flaws are due to improper handling of multipart/mixed e-mail messages
  with many MIME parts and stack consumption by Content-type: message/rfc822
  headers via a large e-mail message.";
tag_solution = "No solution or patch is available as of 15th December, 2008. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.symantec.com/norton/index.jsp";
tag_summary = "This host has Norton AntiVius in Norton Internet Security installed
  and is prone to Denial of Service Vulnerability.";

if(description)
{
  script_id(800321);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5427");
  script_name("Norton Internet Security Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://mime.recurity.com/cgi-bin/twiki/view/Main/AttackIntro");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/499038/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/499045/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of Norton AntiVirus");
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
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Check for Norton Internet Security install
if(!registry_key_exists(key:"SOFTWARE\Symantec\Internet Security")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  if("Norton AntiVirus" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    navVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!navVer){
      exit(0);
    }

    # Grep of version Norton AntiVirus 15.5.0.23
    if(navVer =~ "15.5.0.23"){
      security_warning(0);
    }
    exit(0);
  }
}
