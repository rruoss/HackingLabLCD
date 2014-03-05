###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_ssl_certi_sec_bypass_vuln_oct09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft IE CA SSL Certificate Security Bypass Vulnerability - Oct09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Antu sanadi <santu@secpod.com> on 2011-05-18
#  - This plugin is invalidated by secpod_ms09-056.nasl
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
tag_impact = "Successful exploitation will allow attackers to perform man-in-the-middle
  attacks or impersonate trusted servers, which will aid in further attack.
  Impact Level: Application";
tag_affected = "Microsoft IE version 6.x/7.x/8.x";
tag_insight = "Microsoft Internet Explorer fails to properly validate '\0' character in the
  domain name in a signed CA certificate, allowing attackers to substitute
  malicious SSL certificates for trusted ones.";
tag_solution = "No solution or patch is available as of 05th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Internet Explorer and is prone to
  Security Bypass vulnerability.";

if(description)
{
  script_id(801109);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2510");
  script_bugtraq_id(36475);
  script_name("Microsoft IE CA SSL Certificate Security Bypass Vulnerability - Oct09");
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
  script_xref(name : "URL" , value : "http://www.wired.com/threatlevel/2009/07/kaminsky/");
  script_xref(name : "URL" , value : "http://www.networkworld.com/news/2009/073009-more-holes-found-in-webs.html");
  script_xref(name : "URL" , value : "http://www.networkworld.com/news/2009/091709-microsoft-ie-security-hole.html");

  script_description(desc);
  script_summary("Check for the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

## This plugin is invalidated by secpod_ms09-056.nasl 
exit(0);

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(isnull(ieVer)){
  exit(0);
}

# Check for IE version 6.x or 7.x or 8.x
if(ieVer =~ "^(6|7|8)\..*"){
  security_hole(0);
}
