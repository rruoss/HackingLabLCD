###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qqplayer_mov_file_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# QQPlayer MOV File Processing Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012  Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to execution of arbitrary code.
  Impact Level: Application";
tag_affected = "QQPlayer version 3.2.845 and prior.";
tag_insight = "The flaw is due to a boundary error when processing MOV files, Which
  can be exploited to cause a stack based buffer overflow by sending specially
  crafted MOV file with a malicious PnSize value.";
tag_solution = "No solution or patch is available as of 02,January 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.qq.com/";
tag_summary = "This host is installed with QQPlayer and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(802367);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5006");
  script_bugtraq_id(50739);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-02 12:43:57 +0530 (Mon, 02 Jan 2012)");
  script_name("QQPlayer MOV File Processing Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/77266");
  script_xref(name : "URL" , value : "http://1337day.com/exploits/16899");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46924");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71368");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18137/");

  script_description(desc);
  script_summary("Check for the version of QQPlayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get QQplayer path from Registry
qqplName = "SOFTWARE\Tencent\QQPlayer";
if(!registry_key_exists(key:qqplName)){
  exit(0);
}

qqplVer = registry_get_sz(key:qqplName, item:"Version");
if(qqplVer != NULL)
{
  ## Check for QQplayer version 3.2.845 (3.2.845.400)
  if(version_is_less_equal(version:qqplVer, test_version:"3.2.845.400")){
    security_hole(0);
  }
}
