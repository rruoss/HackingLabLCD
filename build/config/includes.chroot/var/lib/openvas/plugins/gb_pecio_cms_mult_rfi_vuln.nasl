##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pecio_cms_mult_rfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Pecio CMS 'template' Multiple Remote File Include Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will let the remote attacker to obtain sensitive
  information or execute malicious PHP code in the context of the webserver
  process.
  Impact Level: Application.";
tag_affected = "Pecio CMS version 2.0.5";

tag_insight = "The flaw is due to an error in the 'post.php', 'article.php',
  'blog.php' and 'home.php', which are not properly validating the input
  data suplied to 'template' parameter.";
tag_solution = "No solution or patch is available as of 09th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://pecio-cms.com/article/downloads";
tag_summary = "This host is running Pecio CMS and is prone to multiple
  remote file inclusion vulnerabilities.";

if(description)
{
  script_id(801444);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-3204");
  script_bugtraq_id(42806);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Pecio CMS 'template' Multiple Remote File Include Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61433");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14815/");
  script_xref(name : "URL" , value : "http://eidelweiss-advisories.blogspot.com/2010/08/pecio-cms-v205-template-multiple-remote.html");

  script_description(desc);
  script_summary("Check for the version of Pecio CMS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_pecio_cms_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}
		

include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
cmsPort = get_http_port(default:80);
if(!get_port_state(cmsPort)){
  exit(0);
}

## GET the version from KB
cmsVer = get_version_from_kb(port:cmsPort,app:"Pecio_CMS");
if(cmsVer)
{
  ## Check the Pecio CMS version equal to 2.0.5
  if(version_is_equal(version:cmsVer, test_version:"2.0.5")){
    security_hole(cmsPort);
  }
}