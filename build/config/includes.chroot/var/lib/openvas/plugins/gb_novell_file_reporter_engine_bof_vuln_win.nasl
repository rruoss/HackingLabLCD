###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_file_reporter_engine_bof_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Novell File Reporter Engine 'RECORD' Processing Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges or cause denial of service.
  Impact Level: System/Application";
tag_affected = "Novell File Reporter Engine version prior to 1.0.2.53";
tag_insight = "The flaw is due to a boundary error in the 'NFREngine.exe' when
  parsing certain tags inside a RECORD element. This can be exploited to
  cause a stack-based buffer overflow via specially crafted packets sent
  to TCP port 3035.";
tag_solution = "Upgrade Novell File Reporter Engine 1.0.2.53 or later,
  For updates refer to http://download.novell.com/Download?buildid=rCAgCcbPH9s~";
tag_summary = "This host is installed with Novell File Reporter engine and is
  prone to buffer overflow vulnerability.";

if(description)
{
  script_id(801959);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2220");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Novell File Reporter Engine 'RECORD' Processing Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45065");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-227/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/518632/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Novell File Reporter Engine");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


if(!registry_key_exists(key:"SOFTWARE\Novell\File Reporter")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  nfrName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Novell File Reporter Engine" >< nfrName)
  {
    nfrVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(nfrVer != NULL)
    {
      ## Check for  Novell File Reporter version less than 1.0.2.53
      if(version_is_less(version:nfrVer, test_version:"1.0.200.53"))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}
