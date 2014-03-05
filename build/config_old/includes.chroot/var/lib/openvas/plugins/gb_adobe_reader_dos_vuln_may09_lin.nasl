##############################################i#################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_dos_vuln_may09_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Adobe Reader Denial of Service Vulnerability (May09)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the attacker cause memory corruption or
  denial of service.

  Impact level: System/Application.";

tag_affected = "Adobe Reader version 9.1 and prior on Linux.";
tag_insight = "These flaws are due to a memory corruption errors in 'customDictionaryOpen'
  and 'getAnnots' methods in the JavaScript API while processing malicious PDF
  files with a long string in the second argument.";
tag_solution = "Upgrade Adobe Reader version 9.3.2 0r later,
  For further updates refer, http://www.adobe.com";
tag_summary = "This host is installed with Adobe Reader and is prone to
  Denial of Service vulnerability.";

if(description)
{
  script_id(800701);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1493", "CVE-2009-1492");
  script_bugtraq_id(34740, 34736);
  script_name("Adobe Reader Denial of Service Vulnerability (May09)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34924");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50146");
  script_xref(name : "URL" , value : "http://packetstorm.linuxsecurity.com/0904-exploits/spell.txt");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("Adobe/Reader/Linux/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

readerVer = get_kb_item("Adobe/Reader/Linux/Version");
readerVer = ereg_replace(pattern:"\_", replace:".", string:readerVer);
if(readerVer == NULL){
  exit(0);
}

# Grep for Adobe Reader version prior to 9.1
if(version_is_less_equal(version:readerVer, test_version:"9.1")){
  security_hole(0);
}