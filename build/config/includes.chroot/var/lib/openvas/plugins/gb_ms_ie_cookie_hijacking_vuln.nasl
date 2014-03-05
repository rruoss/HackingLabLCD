###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_cookie_hijacking_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Internet Explorer Cookie Hijacking Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow remote attackers to read cookie
  files of the victim and impersonate users requests.
  Impact Level: Application";
tag_affected = "Internet Explorer Version 8 and prior and Version 9 Beta.";
tag_insight = "The flaw exists due to the application which does not properly restrict
  cross-zone drag-and-drop actions, allows user-assisted remote attackers
  to read cookie files via vectors involving an IFRAME element with a SRC
  attribute containing a file: URL.";
tag_solution = "No solution or patch is available as of 9th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "The host is installed with Internet Explorer and is prone to cookie
  hijacking vulnerability.";

if(description)
{
  script_id(802202);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2011-2382");
  script_name("Microsoft Internet Explorer Cookie Hijacking Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.networkworld.com/community/node/74259");
  script_xref(name : "URL" , value : "http://www.theregister.co.uk/2011/05/25/microsoft_internet_explorer_cookiejacking/");

  script_description(desc);
  script_summary("Check for the version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
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

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for Microsoft Internet Explorer version <= 8.0.6001.18702 and
# version = 9.0.7930.16406
if(version_is_less_equal(version:ieVer, test_version:"8.0.6001.18702")||
  version_is_equal(version:ieVer, test_version:"9.0.7930.16406")){
  security_warning(0);
}