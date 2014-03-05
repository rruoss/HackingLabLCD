###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_npfoxitreader_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Foxit Reader Plugin URL Processing Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow the attackers to execute arbitrary code
  on the target system.
  Impact Level: System/Application";

tag_affected = "Foxit Reader version 5.4.4.1128 and prior";
tag_insight = "The is flaw is due to a boundary error in the Foxit Reader plugin for
  browsers (npFoxitReaderPlugin.dll) when processing a URL and can be
  exploited to cause a stack-based buffer overflow via an overly long
  file name in the URL.";
tag_solution = "Upgrade to the Foxit Reader version 5.4.5 or later,
  For updates refer to http://www.foxitsoftware.com/Secure_PDF_Reader";
tag_summary = "The host is installed with Foxit Reader and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(803163);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57174);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-24 13:51:25 +0530 (Thu, 24 Jan 2013)");
  script_name("Foxit Reader PDF File Handling Memory Corruption Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/89030");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51733");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027953");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23944");
  script_xref(name : "URL" , value : "http://www.foxitsoftware.com/support/security_bulletins.php#FRD-18");

  script_description(desc);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check the version of Foxit Reader");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_reader_detect.nasl");
  script_require_keys("Foxit/Reader/Ver");
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

## Variable Initialization
foxitVer = "";

## Get the version from KB
foxitVer = get_kb_item("Foxit/Reader/Ver");
if(!foxitVer){
  exit(0);
}

## Check for Foxit Reader Version less or equal to 5.4.4.1128
if(version_is_less_equal(version:foxitVer, test_version:"5.4.4.1128")){
  security_hole(0);
}
