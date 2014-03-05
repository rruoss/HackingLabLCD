###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vmware_prdts_udf_filesys_bof_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# VMware Products UDF File Systems Buffer Overflow Vulnerability (Win)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to execution of arbitrary code.
  Impact Level: System/Application";
tag_solution = "Upgrade to Vmware Player version 3.1.5 or later
  For updates refer to http://www.vmware.com/security/advisories/VMSA-2011-0011.html

  Upgrade to Vmware Workstation version 7.1.5 or later
  For updates refer to http://www.vmware.com/security/advisories/VMSA-2011-0011.html";

tag_affected = "Vmware Player 3.0 before 3.1.5,
  VMware Workstation 7.0 before 7.1.5";
tag_insight = "The flaw is due to an error when handling UDF filesystem images. This can be
  exploited to cause a buffer overflow via a specially crafted ISO image file.";
tag_summary = "The host is installed with VMWare products and are prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(902631);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-3868");
  script_bugtraq_id(49942);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-17 15:15:00 +0530 (Thu, 17 Nov 2011)");
  script_name("VMware Products UDF File Systems Buffer Overflow Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/76060");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46241");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1026139");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2011-0011.html");

  script_description(desc);
  script_summary("Check for the version of VMware Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Buffer overflow");
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
  if(version_in_range(version:vmplayerVer, test_version:"3.0", test_version2:"3.1.4"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for VMware Workstation
vmworkstnVer = get_kb_item("VMware/Workstation/Win/Ver");
if(vmworkstnVer != NULL)
{
  if(version_in_range(version:vmworkstnVer, test_version:"7.0", test_version2:"7.1.4")){
      security_hole(0);
  }
}
