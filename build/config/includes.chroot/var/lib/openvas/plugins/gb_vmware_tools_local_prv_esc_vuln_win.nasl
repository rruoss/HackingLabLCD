###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_tools_local_prv_esc_vuln_win.nasl 16 2013-10-27 13:09:52Z jan $
#
# VMware Tools Local Privilege Escalation Vulnerability (Win)
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
tag_impact = "Successful exploitation could result in guest OS users to modify
  arbitrary memory locations in guest kernel memory and gain privileges.

  Impact Level : System";

tag_solution = "Upgrade VMware Product(s) to below version,
  VMware ACE 1.0.5 build 79846 or later
  www.vmware.com/download/ace/

  VMware Player 1.0.6 build 80404 or later
  www.vmware.com/download/player/

  VMware Server 1.0.5 build 80187 or later
  www.vmware.com/download/server/

  VMware Workstation 5.5.6 build 80404 or later
  www.vmware.com/download/ws/";

tag_affected = "VMware ACE 1.x - 1.0.5 build 79846 on Windows
  VMware Player 1.x - before 1.0.6 build 80404 on Windows
  VMware Server 1.x - before 1.0.5 build 80187 on Windows
  VMware Workstation 5.x - before 5.5.6 build 80404 on Windows";

tag_summary = "The host is installed with VMWare product(s) that are vulnerable
  to local privilege escalation vulnerability.";

tag_insight = "An input validation error is present in the Windows-based VMware HGFS.sys
  driver. Exploitation of this flaw might result in arbitrary code execution
  on the guest system by an unprivileged guest user. The HGFS.sys driver is
  present in the guest operating system if the VMware Tools package is loaded
  on Windows based Guest OS.";

if(description)
{
  script_id(800004);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-09-26 14:12:58 +0200 (Fri, 26 Sep 2008)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2007-5671");
  script_xref(name:"CB-A", value:"08-0093");
  script_name("VMware Tools Local Privilege Escalation Vulnerability (Win)");
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


  script_description(desc);
  script_summary("Check for the version of VMware Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30556");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2008-0009.html");
  exit(0);
}


if(!get_kb_item("VMware/Win/Installed")){ # Is VMWare installed?
  exit(0);
}

# VMware ACE
vmaceVer = get_kb_item("VMware/ACE/Win/Ver");
if(!vmaceVer){
  vmaceVer = get_kb_item("VMware/ACE\Dormant/Win/Ver");
}

if(vmaceVer)
{
  if(ereg(pattern:"^1\.0(\.[0-4])?$", string:vmaceVer)){
    security_warning(0);
  }
  exit(0);
}

# VMware Player
vmplayerVer = get_kb_item("VMware/Player/Win/Ver");
if(vmplayerVer)
{
  if(ereg(pattern:"^1\.0\.[0-5]($|\..*)", string:vmplayerVer)){
    security_warning(0);
  }
  exit(0);
}

# VMware Server
vmserverVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserverVer)
{
  if(ereg(pattern:"^1\.0(\.[0-4])?$", string:vmserverVer)){
    security_warning(0);
  }
  exit(0);
}

# VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer)
{
  if(ereg(pattern:"^5\.([0-4](\..*)?|5(\.[0-5])?)$", string:vmworkstnVer)){
    security_warning(0);
  }
}
