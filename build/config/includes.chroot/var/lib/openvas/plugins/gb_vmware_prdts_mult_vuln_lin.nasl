###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_prdts_mult_vuln_lin.nasl 16 2013-10-27 13:09:52Z jan $
#
# HGFS VmWare Code Execution Vulnerability (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
tag_insight = "VMware Host Guest File System (HGFS) shared folders feature allows users to
  transfer data between a guest operating system and the host operating system.
  A heap buffer overflow exists in VMware HGFS which allows guest system to
  execute code in the context of vmx process on the host.
  The issue exists only when VMWare system has shared folder enabled.

  Successful exploitation requires that the vix.inGuest.enable configuration
  value is enabled";

tag_solution = "Upgrade VMware to,
  VMware Workstation 6.0.4 or later
  www.vmware.com/download/ws/

  VMware Player 2.0.4 or later
  www.vmware.com/download/player/";

tag_impact = "Successful exploitation allow attackers to execute arbitrary
  code on the affected system and local users could bypass certain
  security restrictions or can gain escalated privileges.
  Impact Level: System";
tag_affected = "VMware Player 2.0.x - 2.0.3 on Linux
  VMware Workstation 6.0.x - 6.0.3 on Linux";

tag_summary = "The host is installed with VMWare product(s) that are vulnerable to
  arbitrary code execution vulnerability.";


if(description)
{
  script_id(800003);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-09-25 10:10:31 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-2098");
  script_bugtraq_id(29443);
  script_xref(name:"CB-A", value:"08-0087:");
  script_name("VMCI/HGFS VmWare Code Execution Vulnerability (Linux)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/30476/");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2008-0008.html");

  script_description(desc);
  script_summary("Check for the version of VMware Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("login/SSH/success","VMware/Linux/Installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


if(!get_kb_item("VMware/Linux/Installed")){
  exit(0);
}

# VMWare Player
playerVer = get_kb_item("VMware/Player/Linux/Ver");
if(playerVer)
{
  if(ereg(pattern:"^2\.0(\.[0-3])?($|[^.0-9])", string:playerVer)){
    security_hole(0);
  }
  exit(0);
}

# VMWare Workstation
wrkstnVer = get_kb_item("VMware/Workstation/Linux/Ver");
if(wrkstnVer)
{
  if(ereg(pattern:"^6\.0(\.[0-3])?($|[^.0-9])", string:wrkstnVer)){
    security_hole(0);
  }
  exit(0);
}
