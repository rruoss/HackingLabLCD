###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wow_activex_mult_remote_code_exec_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# WoW ActiveX Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_solution = "No solution or patch is available as of 05th February 2009, Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.eztools-software.com/tools/wow/default.asp

  Workaround: Set the kill-bit for the below CLSID
  {441E9D47-9F52-11D6-9672-0080C88B3613}
  http://support.microsoft.com/kb/240797";

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can compromise the affected remote system.
  Impact Level: System/Application";
tag_affected = "WoW ActiveX Control version 2 and prior on Windows.";
tag_insight = "Flaws are caused as WoW allows remote attackers to,
  - Create and overwrite arbitrary files via 'WriteIniFileString' method.
  - Execute arbitrary programs via the 'ShellExecute' method.
  - Read/Write from/to the registry via unspecified vectors.";
tag_summary = "This host is installed with WoW ActiveX and is prone to Multiple
  Remote Code Execution Vulnerabilities.";

if(description)
{
  script_id(800224);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-05 14:42:09 +0100 (Thu, 05 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0389");
  script_bugtraq_id(33515);
  script_name("WoW ActiveX Multiple Remote Code Execution Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7910");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48337");

  script_description(desc);
  script_summary("Check for the killbit of WOW ActiveX Control");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Check for product WOW ActiveX Control installation
if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                            "\Uninstall\WOW2 ActiveX Control Sample_is1")){
  exit(0);
}

# Vulnerable CLASSID and killbit check
clsid = "{441E9D47-9F52-11D6-9672-0080C88B3613}";
if(is_killbit_set(clsid:clsid) == 0){
  security_hole(0);
}
