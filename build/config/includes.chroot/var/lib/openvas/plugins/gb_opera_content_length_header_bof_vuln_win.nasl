###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_content_length_header_bof_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Opera Browser 'Content-Length' Header Buffer Overflow Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to crash an affected browser
  or execute arbitrary code
  Impact Level: Application";
tag_affected = "Opera version 10.10 through 10.50 on Windows.";
tag_insight = "The flaw is due to a buffer overflow error when processing malformed
  HTTP 'Content-Length:' headers.";
tag_solution = "Upgrade to the opera version 10.51 or later,
  For updates refer to http://www.opera.com/download/?os=windows&list=all";
tag_summary = "The host is installed with Opera Web Browser and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(801317);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-1349");
  script_bugtraq_id(38519);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Opera Browser 'Content-Length' Header Buffer Overflow Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38820");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11622");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/948/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0529");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Mar/1023690.html");


  script_description(desc);
  script_summary("Check for the version of Opera Web Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get Opera version from from KB list
operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

## Check Opera version  10 <= 10.50
if(version_in_range(version:operaVer, test_version:"10.10",test_version2:"10.50")){
  security_hole(0);
}
