###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_absoluteftp_list_cmd_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# AbsoluteFTP 'LIST' Command Remote Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code within the context of the application. Failed attacks may cause a
  denial of service condition.
  Impact Level: System/Application";
tag_affected = "AbsoluteFTP versions 1.9.6 through 2.2.10";
tag_insight = "The flaw is due to a boundary error when processing an overly long
  'LIST' command. This can be exploited to cause a stack-based buffer overflow
  via a specially crafted FTP LIST command.";
tag_solution = "No solution or patch is available as of 10th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.vandyke.com/products/absoluteftp/";
tag_summary = "This host is installed with AbsoluteFTP and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(802271);
  script_version("$Revision: 13 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"creation_date", value:"2011-11-10 16:16:16 +0530 (Thu, 10 Nov 2011)");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_name("AbsoluteFTP 'LIST' Command Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71210");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18102");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/106797/absoluteftp-overflow.txt");

  script_description(desc);
  script_summary("Check for the version of AbsoluteFTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("secpod_smb_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm AbsoluteFTP
key = "SOFTWARE\VanDyke\AbsoluteFTP\Install";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Installed Path
path = registry_get_sz(key:key, item:"Main Directory");
if(!path){
  exit(0);
}

## Get Version from AbsoluteFTP.exe
version = fetch_file_version(sysPath:path, file_name:"AbsoluteFTP.exe");
if(version)
{
  ## Check for AbsoluteFTP versions
  if(version_in_range(version:version, test_version:"1.9.6", test_version2:"2.2.10.252")){
    security_hole(0);
  }
}
