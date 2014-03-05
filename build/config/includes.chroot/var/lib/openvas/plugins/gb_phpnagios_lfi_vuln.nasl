###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpnagios_lfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpNagios 'conf[lang]' Parameter Local File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers to obtain sensitive
  information or execute arbitrary code on the vulnerable web server.
  Impact Level: Application.";
tag_affected = "phpNagios version 1.2.0 and prior.";
tag_insight = "The flaw is due to error in 'menu.php' and is not properly sanitising
  user supplied input data via 'conf[lang]' parameter.";
tag_solution = "No solution or patch is available as of 21st January, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/phpnagios/";
tag_summary = "The host is running phpNagios and is prone to local file include
  Vulnerabilities.";

if(description)
{
  script_id(800438);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4626");
  script_name("phpNagios 'conf[lang]' Parameter Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9611");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53119");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2615");

  script_description(desc);
  script_summary("Check for the version of phpNagios");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_phpnagios_detect.nasl");
  script_family("Web application abuses");
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

pnPort = get_http_port(default:80);
if(!pnPort){
  exit(0);
}

pnVer = get_kb_item("www/" + pnPort + "/phpNagios");

pnVer = eregmatch(pattern:"^(.+) under (/.*)$", string:pnVer);
if(!isnull(pnVer[1]))
{
  # phpNagios version 1.2.0 (3.0)
  if(version_is_less_equal(version:pnVer[1], test_version:"3.0")){
    security_hole(pnPort);
  }
}
