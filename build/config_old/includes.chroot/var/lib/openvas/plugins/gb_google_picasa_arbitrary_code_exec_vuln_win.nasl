###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_picasa_arbitrary_code_exec_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Picasa Insecure Library Loading Arbitrary Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  in the context of the user running the affected application.
  Impact Level: Application";
tag_affected = "Google Picasa versions prior to 3.8";
tag_insight = "The flaw is due to an error when loading executable and library files
  while using the 'Locate on Disk' feature.";
tag_solution = "Upgrade to the Google Picasa 3.8 or later,
  For updates refer to http://picasa.google.com/thanks.html";
tag_summary = "The host is running Google Picasa and is prone to arbitrary code
  execution vulnerability.";

if(description)
{
  script_id(801770);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2011-0458");
  script_bugtraq_id(47031);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Google Picasa Insecure Library Loading Arbitrary Code Execution Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43853");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN99977321/index.html");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0766");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000022.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Google Picasa");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_picasa_detect_win.nasl");
  script_require_keys("Google/Picasa/Win/Ver");
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

## Get the version from KB
picVer = get_kb_item("Google/Picasa/Win/Ver");
if(!picVer){
  exit(0);
}

## Check for Google Chrome Version less than 3.8
if(version_is_less(version:picVer, test_version:"3.8")){
  security_hole(0);
}
