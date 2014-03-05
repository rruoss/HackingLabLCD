###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edir_ncp_mem_crptn_vuln_win.nasl 16 2013-10-27 13:09:52Z jan $
#
# Novell eDirectory NCP Memory Corruption Vulnerability - (Win)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "Upgrade to 8.7.3 SP10 FTF1 or 8.8 SP3, or
  Apply the available patch from below link,
  http://download.novell.com/Download?buildid=DwSGwHlu4pc~
  http://download.novell.com/Download?buildid=wxO984kvjmc~

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation allows attackers to corrupt process memory,
  which will allow remote code execution on the target machines or can cause
  denial of service condition.
  Impact Level: Application";
tag_affected = "Novell eDirectory before 8.7.3 SP10 and 8.8 SP2 on Windows.";
tag_insight = "The flaw is due to a use-after-free error in the NetWare Core
  Protocol(NCP) engine when handling 'Get NCP Extension Information by
  Name' Requests.";
tag_summary = "This host is running Novell eDirectory and is prone to Memory
  Corruption Vulnerability.";

if(description)
{
  script_id(800137);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5038");
  script_bugtraq_id(31956);
  script_name("Novell eDirectory NCP Memory Corruption Vulnerability - (Win)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/32395");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46138");
  script_xref(name : "URL" , value : "http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5037180.html");
  script_xref(name : "URL" , value : "http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5037181.html");

  script_description(desc);
  script_summary("Check for the Version of Novell eDirectory");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

port = 8028;
if(!get_port_state(port))
{
  port = 8030;
  if(!get_port_state(port)){
    exit(0);
  }
}

eDirVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\NDSonNT", item:"DisplayName");
eDirVer = eregmatch(pattern:"Novell eDirectory ([0-9.]+ (SP[0-9]+)?)",
                    string:eDirVer);
if(eDirVer != NULL)
{
  eDirVer = ereg_replace(pattern:" ", string: eDirVer[1], replace:".");
  if(version_in_range(version:eDirVer, test_version:"8.8",
                      test_version2:"8.8.SP2")){
    security_hole(port);
  }
  else if(version_is_less(version:eDirVer, test_version:"8.7.3.SP10")){
    security_hole(port);
  }
}
