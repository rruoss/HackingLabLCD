###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foswiki_csrf_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Foswiki Cross-Site Request Forgery Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to gain administrative
  privileges on the target application and can cause CSRF attack.
  Impact Level: Application";
tag_affected = "Foswiki version prior to 1.0.5";
tag_insight = "An application allowing users to perform certain actions via HTTP requests
  without performing any validity checks to verify the requests.";
tag_solution = "Upgrade to version 1.0.5 or later,
  http://foswiki.org/Download";
tag_summary = "The host is running Foswiki and is prone to Cross-Site Request Forgery
  Vulnerability.";

if(description)
{
  script_id(800613);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1434");
  script_name("Foswiki Cross-Site Request Forgery Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34863");
  script_xref(name : "URL" , value : "http://foswiki.org/Support/SecurityAlert-CVE-2009-1434");

  script_description(desc);
  script_summary("Check for the Version of Foswiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_foswiki_detect.nasl");
  script_require_ports("Services/www", 80);
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

foswikiPort = get_http_port(default:80);

if(!foswikiPort){
  exit(0);
}

foswikiVer = get_kb_item("www/" + foswikiPort + "/Foswiki");

if(foswikiVer != NULL)
{
  foswikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:foswikiVer);
  if(foswikiVer[1] != NULL)
  {
    if(version_is_less(version:foswikiVer[1], test_version:"1.0.5")){
      security_hole(foswikiPort);
    }
  }
}
