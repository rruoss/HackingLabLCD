###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_notes_url_cmd_inj_rce_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# IBM Lotus Notes URL Command Injection RCE Vulnerability (Win)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code via a
  malicious URLs.
  Impact Level: System/Application";

tag_affected = "IBM Lotus Notes Version 8.x before 8.5.3 FP2 on windows";
tag_insight = "An error exists within the URL handler which allows attackers to execute
  commands on the target.";
tag_solution = "Upgrade to IBM Lotus Notes 8.5.3 FP2 or later,
  For updates refer to http://www-304.ibm.com/support/docview.wss?uid=swg21598348";
tag_summary = "This host is installed with IBM Lotus Notes and is prone to remote
  code execution vulnerability.";

if(description)
{
  script_id(803214);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-2174");
  script_bugtraq_id(54070);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-23 11:08:14 +0530 (Wed, 23 Jan 2013)");
  script_name("IBM Lotus Notes URL Command Injection RCE Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/83063");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49601");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027427");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75320");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23650");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-12-154");
  script_xref(name : "URL" , value : "http://www-304.ibm.com/support/docview.wss?uid=swg21598348");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/119058/IBM-Lotus-Notes-Client-URL-Handler-Command-Injection.html");

  script_description(desc);
  script_summary("Check for the version of IBM Lotus Notes on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ibm_lotus_notes_detect_win.nasl");
  script_require_keys("IBM/LotusNotes/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

lotusVer = "";

## Get for IBM Lotus Notes Version
lotusVer = get_kb_item("IBM/LotusNotes/Win/Ver");
if(!lotusVer){
  exit(0);
}

## Check for IBM Lotus Notes Version 8.x < 8.5.3 FP2 [8.5.32.12184]
if(lotusVer =~ "^8" &&
   version_is_less(version:lotusVer, test_version:"8.5.32.12184")){
  security_hole(0);
}
