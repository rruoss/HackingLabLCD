###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wincomlpd_total_mult_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# WinComLPD Total Multiple Vulnerabilities
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
tag_impact = "Successful exploitation could allow execution of arbitrary code or
  crashing the remote wincomlpd service by simply using negative values like
  0x80/0xff for the 8 bit numbers and 0x8000/0xffff for the data blocks.
  Impact Level: System";
tag_affected = "WinCom LPD Total 3.0.2.623 and prior on Windows.";
tag_insight = "The issues are due to,
  - an error in Line Printer Daemon Service (LPDService.exe), when processing
    print jobs with an overly long control file on default TCP port 515/13500.
  - an error in authentication checks in the Line Printer Daemon (LPD).";
tag_solution = "No solution or patch is available as of 26th November, 2008. Information
  regarding this issue will be updated once the solution details are
  available.
  For updates refer to http://www.clientsoftware.com.au/download.php";
tag_summary = "This host is installed with WinComLPD Total and is prone to buffer
  overflow and authentication bypass vulnerabilities.";

if(description)
{
  script_id(800063);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5158", "CVE-2008-5159", "CVE-2008-5176");
  script_bugtraq_id(27614);
  script_name("WinComLPD Total Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28763");
  script_xref(name : "URL" , value : "http://aluigi.org/adv/wincomalpd-adv.txt");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/0410");

  script_description(desc);
  script_summary("Check for the Version of WinCom LPD Total");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
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
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

lpdport = 515;
if(!get_port_state(lpdport))
{
  lpdport = 13500;
  if(!get_port_state(lpdport)){
    exit(0);
  }
}

lpdVer = registry_get_sz(key:"SYSTEM\CurrentControlSet\Services\LPDService",
                         item:"ImagePath");
if(!lpdVer){
  exit(0);
}

share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:lpdVer);
file =  ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:lpdVer);

lpdVer = GetVer(file:file, share:toupper(share));
if(!lpdVer){
  exit(0);
}

if(version_is_less_equal(version:lpdVer, test_version:"3.0.2.623")){
  security_hole(lpdport);
}
