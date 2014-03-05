###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_info_disclosure_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Drupal Information Disclosure Vulnerability
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
tag_impact = "Attackers can exploit this issue to obtain that set of credentials which
  are included in the generated links.
  Impact Level: Application";
tag_affected = "Drupal Version 5.x before 5.19 and 6.x before 6.13 on all platforms.";
tag_insight = "Application fails to sanitize login attempts for pages that contain a sortable
  table, which includes the username and password in links that can be read from
  the HTTP referer header of external web sites that are visited from those links
  or when page caching is enabled, the Drupal page cache.";
tag_solution = "Upgrade to Drupal 5.19 or 6.13 or later
  http://drupal.org";
tag_summary = "The host is installed with Drupal and is prone to Information
  Disclosure vulnerability.";

if(description)
{
  script_id(800909);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2374");
  script_bugtraq_id(35548);
  script_name("Drupal Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://drupal.org/node/507572");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35657");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Jul/1022497.html");

  script_description(desc);
  script_summary("Check for the Version of Drupal");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

drPort = get_http_port(default:80);
if(!drPort){
  exit(0);
}

drupalVer = get_kb_item(string("www/", drPort, "/drupal"));
drupalVer = eregmatch(pattern:"^(.+) under (/.*)$", string:drupalVer);

if(!drupalVer[1]){
  exit(0);
}

# Check for Drupal Version 5.0 < 5.19 and 6.0 < 6.13
if(version_in_range(version:drupalVer[1], test_version:"5.0", test_version2:"5.18") ||
   version_in_range(version:drupalVer[1], test_version:"6.0", test_version2:"6.12")){
  security_warning(drPort);
}
