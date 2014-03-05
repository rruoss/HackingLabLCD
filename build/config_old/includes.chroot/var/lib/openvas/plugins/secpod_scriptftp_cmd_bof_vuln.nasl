###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_scriptftp_cmd_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# ScriptFTP 'GETLIST' or 'GETFILE' Commands Remote Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_affected = "ScriptFTP version 3.3 and prior.";
tag_insight = "The flaw is due to a boundary error when processing filenames within
  a directory listing. This can be exploited to cause a stack-based buffer
  overflow via a specially crafted FTP LIST command response.";
tag_solution = "No solution or patch is available as of 23rd September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.scriptftp.com/download.php";
tag_summary = "This host is installed with ScriptFTP and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(902571);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_bugtraq_id(49707);
  script_cve_id("CVE-2011-3976");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("ScriptFTP 'GETLIST' or 'GETFILE' Commands Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46099/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17876/");
  script_xref(name : "URL" , value : "http://www.digital-echidna.org/2011/09/scriptftp-3-3-remote-buffer-overflow-exploit-0day/");

  script_description(desc);
  script_summary("Check for the version of ScriptFTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Confirm ScriptFTP
key = "SOFTWARE\ScriptFTP";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Installed Path
path = registry_get_sz(key:key, item:"Install_Dir");
if(!path){
  exit(0);
}

## Get Version from ScriptFTP.exe
version = fetch_file_version(sysPath:path, file_name:"ScriptFTP.exe");
if(version)
{
  ## Check for ScriptFTP version 3.3 and prior.
  if(version_is_less_equal(version:version, test_version:"3.3")) {
    security_hole(0);
  }
}
