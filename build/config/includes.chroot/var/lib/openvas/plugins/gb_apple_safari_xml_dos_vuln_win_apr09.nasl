###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_xml_dos_vuln_win_apr09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apple Safari Denial of Service Vulnerability (Win) - Apr09
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Attacker could exploit this vulnerability to cause the browser to crash.
  Impact Level: Application";
tag_affected = "Apple Safari version 4 beta and prior on Windows.";
tag_insight = "Improper parsing of XML documents while persuading a victim to open a
  specially-crafted XML document containing an overly large number of nested
  elements crashes the Browser.";
tag_solution = "No solution or patch is available as of 06th April, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.apple.com/support/downloads";
tag_summary = "This host is running Apple Safari Web Browser and is prone
  to denial of service vulnerability.";

if(description)
{
  script_id(800549);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-07 07:29:53 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1233");
  script_bugtraq_id(34318);
  script_name("Apple Safari Denial of Service Vulnerability (Win) - Apr09");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8325");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49527");

  script_description(desc);
  script_summary("Check for the version of Apple Safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
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

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

# Apple Safari Version <= (4.28.16.0) 4 build 528.16
if(version_is_less_equal(version:safariVer, test_version:"4.28.16.0")){
  security_warning(0);
}
