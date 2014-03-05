###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_authorization_service_dos_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# VMware Authorization Service Denial of Service Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allow attackers to execute arbitrary code on the
  affected application and causes the Denial of Service.
  Impact Level: Application";
tag_affected = "VMware ACE 2.5.3 and prior.
  VMware Player 2.5.3 build 185404 and prior.
  VMware Workstation 6.5.3 build 185404 and prior.";
tag_insight = "The vulnerability is due to an error in the VMware Authorization
  Service when processing login requests. This can be exploited to terminate
  the 'vmware-authd' process via 'USER' or 'PASS' strings containing '\xFF'
  characters, sent to TCP port 912.";
tag_solution = "No solution or patch is available as of 22nd October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.vmware.com/";
tag_summary = "The host is installed with VMWare product(s) that are vulnerable to
  Denial of Service vulnerability.";

if(description)
{
  script_id(801027);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3707");
  script_name("VMware Authorization Service Denial of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36988");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Oct/1022997.html");

  script_description(desc);
  script_summary("Check for the version of VMware Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_require_keys("VMware/Win/Installed", "VMware/Player/Win/Ver",
                      "VMware/Workstation/Win/Ver", "VMware/ACE/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

# VMware Player
vmpVer = get_kb_item("VMware/Player/Win/Ver");
if(vmpVer)
{
  if(version_in_range(version:vmpVer, test_version:"2.0", test_version2:"2.5.3"))
  {
    security_warning(0);
    exit(0);
  }
}

# VMware Workstation
vmwtnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmwtnVer)
{
  if(version_in_range(version:vmwtnVer, test_version:"6.0", test_version2:"6.5.3"))
  {
    security_warning(0);
    exit(0);
  }
}

# VMware ACE
aceVer = get_kb_item("VMware/ACE/Win/Ver");
if(aceVer)
{
  if(version_in_range(version:aceVer, test_version:"2.0", test_version2:"2.5.3")){
    security_warning(0);
  }
}
