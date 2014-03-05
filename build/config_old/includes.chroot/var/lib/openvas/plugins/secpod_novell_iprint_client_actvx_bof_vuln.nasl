###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_iprint_client_actvx_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Novell iPrint Client ActiveX Control Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploits allow remote attackers to execute arbitrary code in the
  context of the application using the ActiveX control (typically Internet
  Explorer). Failed exploit attempts will likely result in denial-of-service
  conditions.
  Impact Level: System/Application";
tag_affected = "Novell iPrint Client version 4.38 and prior on Windows.";
tag_insight = "The flaw is due to an unspecified buffer-overflow errors, because the
  application fails to perform boundary checks on user-supplied data.";
tag_solution = "Upgrade to Novell iPrint Client version 5.40 or later,
  For updates refer to http://download.novell.com/index.jsp";
tag_summary = "This host has Novell iPrint Client installed and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_id(900852);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3176");
  script_bugtraq_id(36231);
  script_name("Novell iPrint Client ActiveX Control Buffer Overflow Vulnerability");
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
  script_summary("Check for the version of Novell iPrint Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
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
  script_xref(name : "URL" , value : "http://intevydis.com/vd-list.shtml");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36579/");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")) {
  exit(0);
}

# Grep the Novell iPrint Client version from Registry
ver = registry_get_sz(key:"SOFTWARE\Novell-iPrint", item:"Current Version");
if(!ver) {
  exit(0);
}

iprintVer = eregmatch(pattern:"v([0-9.]+)", string:ver);
if(iprintVer[1] != NULL)
{
  # Check for Novell iPrint Client version < 4.38
  if(version_is_less_equal(version:iprintVer[1], test_version:"4.38")){
    security_hole(0);
  }
}
