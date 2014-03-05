###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_neoaxis_web_player_zip_file_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# NeoAxis Web Player Zip File Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "NeoAxis web player version 1.4 and prior";
tag_insight = "The flaw is caused due by improper validation of the files extracted from
  neoaxis_web_application_win32.zip file, which allows attackers to write
  arbitrary files via directory traversal attacks.";
tag_solution = "No solution or patch is available as of 1st February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.neoaxis.com/";
tag_summary = "This host is installed with NeoAxis Web Player and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(802601);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51666);
  script_cve_id("CVE-2012-0907");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-01 14:14:14 +0530 (Wed, 01 Feb 2012)");
  script_name("NeoAxis Web Player Zip File Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/78311");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51666");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72427");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/neoaxis_1-adv.txt");

  script_description(desc);
  script_summary("Check for the version of NeoAxis Web Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Registry Key
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NeoAxis Web Player_is1";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Confirm The Application
name = registry_get_sz(key:key, item:"DisplayName");
if("NeoAxis Web Player" >< name)
{
  ## Get version
  version = registry_get_sz(key:key, item:"DisplayVersion");

  ## Check for NeoAxis web player version 1.4 and prior.
  if(version && version_is_less_equal(version:version, test_version:"1.4")){
    security_hole(0);
  }
}
