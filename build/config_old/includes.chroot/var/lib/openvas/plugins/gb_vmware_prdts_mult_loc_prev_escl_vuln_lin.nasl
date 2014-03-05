###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_mult_loc_prev_escl_vuln_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# VMware Products Multiple Local Privilege Escalation Vulnerabilities (Linux)
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
tag_solution = "Apply the patch or upgrade workstation 7.1.2 build 301548
  http://www.vmware.com/products/ws/

  Apply the patch Upgrade to 3.1.2 build 301548
  http://www.vmware.com/products/player/

  For VMware Server version 2.x ,
  No solution or patch is available as of 09th December 2010. Information
  regarding this issue will be updated once the solution details are available.
  http://downloads.vmware.com/d/info/datacenter_downloads/vmware_server/2_0

  *****
  NOTE: Ignore this warning, if above mentioned workaround is manually applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code with
  elevated privileges, this may aid in other attacks.
  Impact Level: System/Application";
tag_summary = "The host is installed with VMWare products multiple local privilege
  escalation Vulnerabilities.";

tag_affected = "VMware Server version  2.x
  VMware Player 3.x before 3.1.2 build 301548
  VMware Workstation 7.x before 7.1.2 build 301548 on Linux";
tag_insight = "The flaws are due to
  - Race conditions within the 'vmware-mount' utility when handling temporary
    files during the mounting process can be exploited to create files or
    directories.
  - An error within the 'vmware-mount' utility when loading libraries that can
    be exploited to execute arbitrary code with root privileges.";

if(description)
{
  script_id(801559);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2010-4295", "CVE-2010-4296");
  script_bugtraq_id(45167, 45168);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("VMware Products Multiple Local Privilege Escalation Vulnerabilities (Linux)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/42453/");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2010-0018.html");
  script_xref(name : "URL" , value : "http://lists.vmware.com/pipermail/security-announce/2010/000112.html");

  script_description(desc);
  script_summary("Check for the version of VMware Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_require_keys("VMware/Linux/Installed");
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

if(!get_kb_item("VMware/Linux/Installed")){
  exit(0);
}

# Check for VMware Player
vmplayerVer = get_kb_item("VMware/Player/Linux/Ver");
if(vmplayerVer != NULL )
{
  if(version_in_range(version:vmplayerVer, test_version:"3.0", test_version2:"3.1.1"))
  {
    security_hole(0);
    exit(0);
  }
}

#Check for VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(vmworkstnVer != NULL)
{
  if(version_in_range(version:vmworkstnVer, test_version:"7.0", test_version2:"7.1.1"))
  {
    security_hole(0);
    exit(0);
  }
}

# VMware Server
vmserVer = get_kb_item("VMware/Server/Linux/Ver");
if(vmserVer)
{
  if(vmserVer =~ "^2.*"){
   security_hole(0);
  }
}
