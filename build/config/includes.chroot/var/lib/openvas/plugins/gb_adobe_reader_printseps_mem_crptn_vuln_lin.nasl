###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_printseps_mem_crptn_vuln_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Reader 'printSeps()' Function Heap Corruption Vulnerability
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
tag_impact = "Successful exploitation will let attackers to crash an affected application
  or compromise a vulnerable system by tricking a user into opening a specially
  crafted PDF file.
  Impact Level:Application";
tag_affected = "Adobe Reader version 8.x to 8.1.7 and 9.x before 9.4.1 on Linux";
tag_insight = "This issue is caused by a heap corruption error in the 'EScript.api' plugin
  when processing the 'printSeps()' function within a PDF document.";
tag_solution = "Upgrade to Adobe Reader/Acrobat version 9.4.1 or later,
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Reader and is prone to heap
  corruption Vulnerability";

if(description)
{
  script_id(801546);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2010-4091");
  script_bugtraq_id(44638);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Reader 'printSeps()' Function Heap Corruption Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42095");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62996");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15419/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2890");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/psirt/2010/11/potential-issue-in-adobe-reader.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("Adobe/Reader/Linux/Version");
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

readerVer = get_kb_item("Adobe/Reader/Linux/Version");
if(!readerVer){
  exit(0);
}

# Check for Adobe Reader version < 8.1.7 and 9.x to 9.4.0
if(version_is_less(version:readerVer, test_version:"8.1.7") ||
   version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.0")){
    security_hole(0);
}
