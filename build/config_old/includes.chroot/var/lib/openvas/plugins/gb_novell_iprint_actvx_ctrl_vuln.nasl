###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_iprint_actvx_ctrl_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Novell iPrint ActiveX control Stack-based BOF Vulnerability
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
tag_impact = "Successful attack could lead to execution of arbitrary code via a long target
  frame option value, which crashes the browser and may allow code execution.
  Impact Level: Application";
tag_affected = "Novell iPrint Client version 5.06 and prior on Windows.";
tag_insight = "The issue is due to the improper handling of user requests sent to the
  ExecuteRequest method in ienipp.ocx file.";
tag_solution = "No solution or patch is available as of 27th November, 2008. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://download.novell.com/index.jsp";
tag_summary = "The host is installed with Novell iPrint, and is prone to stack
  based buffer overflow vulnerability.";

if(description)
{
  script_id(800070);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5231");
  script_name("Novell iPrint ActiveX control Stack-based BOF Vulnerability");
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
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-5231");

  script_description(desc);
  script_summary("Check for the version of Novel iPrint");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

iPrintVer = registry_get_sz(key:"SOFTWARE\Novell-iPrint",
                            item:"Current Version");
if(!iPrintVer){
  exit(0);
}

novVer = eregmatch(pattern:"v([0-9.]+)", string:iPrintVer);
if(novVer[1] != NULL)
{
  if(version_is_less_equal(version:novVer[1], test_version:"5.06")){
    security_hole(0);
  }
}
