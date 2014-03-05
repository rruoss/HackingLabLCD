###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_csrf_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# TWiki Cross-Site Request Forgery Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_affected = "TWiki version prior to 4.3.1";
tag_insight = "Remote authenticated user can create a specially crafted image tag that,
  when viewed by the target user, will update pages on the target system
  with the privileges of the target user via HTTP requests.";
tag_solution = "Upgrade to version 4.3.1 or later,
  http://twiki.org/cgi-bin/view/Codev/DownloadTWiki";
tag_summary = "The host is running TWiki and is prone to Cross-Site Request
  Forgery Vulnerability.";

if(description)
{
  script_id(800400);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1339");
  script_name("TWiki Cross-Site Request Forgery Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34880");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=526258");
  script_xref(name : "URL" , value : "http://twiki.org/p/pub/Codev/SecurityAlert-CVE-2009-1339/TWiki-4.3.0-c-diff-cve-2009-1339.txt");

  script_description(desc);
  script_summary("Check for the Version of TWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
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

twikiPort = get_http_port(default:80);
if(!twikiPort){
  exit(0);
}

twikiVer = get_kb_item("www/" + twikiPort + "/TWiki");
twikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:twikiVer);
if(twikiVer[1] != NULL)
{
  if(version_is_less(version:twikiVer[1], test_version:"4.3.1")){
    security_hole(twikiPort);
  }
}
