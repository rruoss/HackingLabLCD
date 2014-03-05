###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_mult_spoof_vuln_lin_dec09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Firefox Multiple Spoofing Vulnerabilies - dec09 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to conduct spoofing attacks and
  possibly launch further attacks on the system.
  Impact Level:System/Application";
tag_affected = "Mozilla Firefox version 3.0 to 3.5.5 on Linux.";
tag_insight = "- A race condition error allows attackers to produce a JavaScript message with
    a spoofed domain association by writing the message in between the document
    request and document load for a web page in a different domain.
  - Visual truncation vulnerability in the MakeScriptDialogTitle function in
    nsGlobalWindow.cpp in Mozilla Firefox allows remote attackers to spoof the
    origin domain name of a script via a long name.";
tag_solution = "Upgrade to Firefox version 3.6.3 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/firefox.html";
tag_summary = "The host is installed with Firefox browser and is prone to multiple
  spoofing vulnerabilies.";

if(description)
{
  script_id(801094);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4129", "CVE-2009-4130");
  script_bugtraq_id(37230, 37232);
  script_name("Mozilla Firefox Multiple Spoofing Vulnerabilies - dec09 (Linux)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54612");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54611");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Dec/1023287.html");

  script_description(desc);
  script_summary("Check for the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
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

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer){
  exit(0);
}

# Grep for Firefox version 3.0 to 3.5.5
if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.5.5")){
  security_hole(0);
}
