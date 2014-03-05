###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_mem_corruption_n_bof_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# VMware Products Memory Corruption and Buffer Overflow Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_solution = "Apply the patch or upgrade workstation 6.5.5 build 328052 or 7.1.2 build 301548
  http://www.vmware.com/products/ws/

  Apply the patch Upgrade to VMware player 2.5.5 build 246459 and 3.1.2 build 301548
  http://www.vmware.com/products/player/

  For VMware Server version 2.x ,
  No solution or patch is available as of 09th December 2010. Information
  regarding this issue will be updated once the solution details are available.
  http://downloads.vmware.com/d/info/datacenter_downloads/vmware_server/2_0

  *****
  NOTE: Ignore this warning, if above mentioned workaround is manually applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to corrupt heap memory by
  tricking a user into visiting a malicious website or playing a malicious
  file.
  Impact Level: System/Application";
tag_summary = "The host is installed with VMWare products and are prone to memory
  corruption and buffer overflow Vulnerability";

tag_affected = "VMware Server version  2.x
  VMware Player 2.5.x before 2.5.5 build 246459 and 3.x before 3.1.2 build 301548
  VMware Workstation 6.5.x before 6.5.5 build 328052 and 7.x before 7.1.2 build 301548";
tag_insight = "The flaw is due to the VMnc codec 'vmnc.dll' driver which does not
  properly verify the size when handling 'ICM_DECOMPRESS' driver messages,
  which can be exploited to corrupt heap memory.";

if(description)
{
  script_id(801558);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2010-4294");
  script_bugtraq_id(45169);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("VMware Products Memory Corruption and Buffer Overflow Vulnerability (Win)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/42481");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2010-0018.html");
  script_xref(name : "URL" , value : "http://lists.vmware.com/pipermail/security-announce/2010/000112.html");

  script_description(desc);
  script_summary("Check for the version of VMware Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_require_keys("VMware/Win/Installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

# Check for VMware Player
vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer != NULL )
{
  if(version_in_range(version:vmplayerVer, test_version:"2.5", test_version2:"2.5.4") ||
     version_in_range(version:vmplayerVer, test_version:"3.0", test_version2:"3.1.1"))
  {
    security_hole(0);
    exit(0);
  }
}

#Check for VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer != NULL)
{
  if(version_in_range(version:vmworkstnVer, test_version:"6.5", test_version2:"6.5.4") ||
     version_in_range(version:vmworkstnVer, test_version:"7.0", test_version2:"7.1.11"))
  {
    security_hole(0);
    exit(0);
  }
}

# VMware Server
vmserVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserVer)
{
  if(vmserVer =~ "^2.*"){
   security_hole(0);
  }
}
