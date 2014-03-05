###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ca_activex_mult_code_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Computer Associates WebScan ActiveX Control Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_solution = "No solution or patch is available as of 14th June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=238635

  Workaround:
  Set the killbit for the following CLSIDs,
  {56393399-041A-4650-94C7-13DFCB1F4665}, {7B297BFD-85E4-4092-B2AF-16A91B2EA103}";

tag_impact = "Successful exploitation will let the remote attackers execute arbitrary code
  and can compromise a vulnerable system.
  Impact Level: System";
tag_affected = "PSFormX ActiveX control with CLSID {56393399-041A-4650-94C7-13DFCB1F4665}
  WebScan ActiveX control with CLSID {7B297BFD-85E4-4092-B2AF-16A91B2EA103}";
tag_insight = "Multiple unspecified errors in the CA PSFormX and WebScan ActiveX controls,
  allow remote attackers to execute arbitrary code via unknown vectors.";
tag_summary = "This host is installed with CA PSFormX or WebScan ActiveX controls
  and is prone to multiple remote code execution vulnerabilities.";

if(description)
{
  script_id(801225);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_bugtraq_id(40689, 40494);
  script_cve_id("CVE-2010-2193");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Computer Associates WebScan ActiveX Control Multiple Remote Code Execution Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS10-034.mspx");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511764/100/0/threaded");
  script_xref(name : "URL" , value : "https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=238635");

  script_description(desc);
  script_summary("Check for the CLSID");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
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
include("secpod_activex.inc");

## Confirm Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## CLSID List
clsids = make_list("{56393399-041A-4650-94C7-13DFCB1F4665}",
                   "{7B297BFD-85E4-4092-B2AF-16A91B2EA103}");

foreach clsid (clsids)
{
  ## Check if Kill-Bit is set
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_hole(0);
    exit(0);
  }
}
