###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fathftp_client_mult_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# FathFTP ActiveX Control Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allows remote attackers to cause a denial of
  service or possibly execute arbitrary code.
  Impact Level: Application.";
tag_affected = "FathFTP version 1.7";

tag_insight = "The flaws are due to errors in the handling of 'GetFromURL' member and
  long argument to the 'RasIsConnected' method, which allow remote attackers
  to execute arbitrary code.";
tag_solution = "No solution or patch is available as of 15th July, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.fathsoft.com/download.html";
tag_summary = "This host is installed with FathFTP and is prone to multiple buffer
  overflow vulnerabilities.";

if(description)
{
  script_id(801379);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2701");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("FathFTP ActiveX Control Multiple Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60200");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14269/");

  script_description(desc);
  script_summary("Check for the version of FathFTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FathFTP component_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for  FathFTP DisplayName
fftpName = registry_get_sz(key:key, item:"DisplayName");
if("FathFTP" >< fftpName)
{
  fftpVer = eregmatch(pattern:"version ([0-9.]+)", string:fftpName);
  if(fftpVer[1])
  {
    ## Check for the FathFTP version equal to 1.7
    if(version_is_equal(version:fftpVer[1], test_version:"1.7")){
      security_hole(0);
    }
  }
}
