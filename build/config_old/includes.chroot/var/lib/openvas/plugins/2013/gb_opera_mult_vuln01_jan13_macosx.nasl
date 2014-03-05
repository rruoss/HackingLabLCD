###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln01_jan13_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# Opera Multiple Vulnerabilities-01 Jan13 (Mac OS X)
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
tag_impact = "Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or spoofing the address.
  Impact Level: System/Application";

tag_affected = "Opera version before 12.12 on Mac OS X";
tag_insight = "- Malformed GIF images could allow execution of arbitrary code.
  - Repeated attempts to access a target site can trigger address field
    spoofing.";
tag_solution = "Upgrade to Opera version 12.12 or later,
  For updates refer to http://www.opera.com/";
tag_summary = "The host is installed with Opera and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803139);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-6470", "CVE-2012-6471");
  script_bugtraq_id(56788, 56984);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-07 14:14:34 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Multiple Vulnerabilities-01 Jan13 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1038/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1040/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unified/1212/");

  script_description(desc);
  script_summary("Check for the version of Opera for Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl", "ssh_authorization_init.nasl");
  script_require_keys("Opera/MacOSX/Version");
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

operaVer = "";

## Get Opera version from KB
operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

## Check for opera versions prior to 12.12
if(version_is_less(version:operaVer, test_version:"12.12")){
  security_hole(0);
}
