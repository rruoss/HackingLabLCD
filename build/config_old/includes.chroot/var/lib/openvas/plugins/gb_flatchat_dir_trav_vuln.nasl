###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flatchat_dir_trav_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Flatchat Directory Traversal Vulnerability
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
tag_impact = "Successful attacks can cause inclusion or execution of arbitrary local files
  in the context of the webserver process via directory traversal attacks and
  URL-encoded NULL-bytes.
  Impact Level: Application";
tag_affected = "Flatchat version 3.0 and prior";
tag_insight = "Improper handling of user supplied input into the  pmscript.php file via
  ..(dot dot) in 'with' parameter, can lead to directory traversal.";
tag_solution = "No solution or patch is available as of 18th May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://ninjadesigns.co.uk/";
tag_summary = "The host is running Flatchat and is prone to Directory Traversal
  vulnerability.";

if(description)
{
  script_id(800323);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1486");
  script_bugtraq_id(34734);
  script_name("Flatchat Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34904");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8549");

  script_description(desc);
  script_summary("Check for the Version of Flatchat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flatchat_detect.nasl");
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

flatchatPort = get_http_port(default:80);
if(!flatchatPort){
  exit(0);
}

fcVer = get_kb_item("www/" + flatchatPort + "/Flatchat");
fcVer = eregmatch(pattern:"^(.+) under (/.*)$", string:fcVer);

if(fcVer[1] != NULL)
{
  if(version_is_less_equal(version:fcVer[1], test_version:"3.0")){
    security_hole(flatchatPort);
  }
}
