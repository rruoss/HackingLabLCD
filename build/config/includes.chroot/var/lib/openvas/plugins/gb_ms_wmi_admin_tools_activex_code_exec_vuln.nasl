###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_wmi_admin_tools_activex_code_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft WMI Administrative Tools ActiveX Control Remote Code Execution Vulnerabilities
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
tag_solution = "No solution or patch is available as of 27th December, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.microsoft.com/downloads/en/details.aspx?FamilyID=6430f853-1120-48db-8cc5-f2abdc3ed314

  Workaround:
  Set the killbit for the following CLSID:
  {2745E5F5-D234-11D0-847A-00C04FD7BB08}";

tag_impact = "Successful exploitation will let the remote attackers execute arbitrary code
  and can compromise a vulnerable system.
  Impact Level: System";
tag_affected = "Microsoft WMI Administrative Tools 1.1";
tag_insight = "The flaws are due to the 'AddContextRef()' and 'ReleaseContext()'
  methods in the WMI Object Viewer Control using a value passed in the
  'lCtxHandle' parameter as an object pointer.";
tag_summary = "This host is installed with Microsoft WMI Administrative Tools
  and is prone to multiple remote code execution vulnerabilities.";

if(description)
{
  script_id(801677);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_bugtraq_id(45546);
  script_cve_id("CVE-2010-3973", "CVE-2010-4588");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft WMI Administrative Tools ActiveX Control Remote Code Execution Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42693");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/725596");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3301");
  script_xref(name : "URL" , value : "http://www.wooyun.org/bug.php?action=view&amp;id=1006");
  exit(0);
}

include("smb_nt.inc");
include("secpod_activex.inc");

## Confirm Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## CLSID
clsid = "{2745E5F5-D234-11D0-847A-00C04FD7BB08}";

## Check if Kill-Bit is set
if(is_killbit_set(clsid:clsid) == 0){
  security_hole(0);
}
