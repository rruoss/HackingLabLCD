###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_pgc_insecure_lib_load_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows Progman Group Converter Insecure Library Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code and
  conduct DLL hijacking attacks via a Trojan horse 'imm.dll'.
  Impact Level: System";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 23 Service Pack 2 and prior
  Microsoft Windows 2000 Service Pack 4 and prior";
tag_insight = "The flaw is due to Windows Progman Group Converter (grpconv.exe) which
  loads libraries in an insecure manner.";
tag_solution = "No solution or patch is available as of 04th October, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/en/us/default.aspx.";
tag_summary = "The host is installed Microsoft Windows Progman Group Converter and
  is prone to insecure library loading vulnerability.";

if(description)
{
  script_id(801456);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-3139");
  script_name("Microsoft Windows Progman Group Converter Insecure Library Loading Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41136");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14758/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2200");

  script_description(desc);
  script_summary("Check for the existance of file grpconv.exe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
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
include("secpod_reg.inc");
include("secpod_smb_func.inc");

exit(0); ## plugin may results to FP

if(hotfix_check_sp(xp:4, win2003:3, win2k:5) <= 0){
  exit(0);
}

## Get the path of the vuln file
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\grpconv.exe");

## Check for the existance of the file
exeSize = get_file_size(file:file, share:share);
if(exeSize != NULL){
  security_hole(0);
}
