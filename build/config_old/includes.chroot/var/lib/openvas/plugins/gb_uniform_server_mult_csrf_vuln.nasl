##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_uniform_server_mult_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Uniform Server Multiple Cross-Site Request Forgery Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to change the administrator's
  password by tricking a logged in administrator into visiting a malicious
  web site.
  Impact Level: Application.";
tag_affected = "Uniform Server version 5.6.5 and prior.";

tag_insight = "The application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the requests.";
tag_solution = "No solution or patch is available as of 03rd June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.uniformserver.com/";
tag_summary = "This host is running Uniform Server and is prone to multiple
  Cross-Site Request Forgery vulnerabilities.";

if(description)
{
  script_id(800787);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2113");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Uniform Server Multiple Cross-Site Request Forgery Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/64858");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39913");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58844");
  script_xref(name : "URL" , value : "http://cross-site-scripting.blogspot.com/2010/05/uniform-server-565-xsrf.html");

  script_description(desc);
  script_summary("Check for the version of Uniform Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_uniform_server_detect.nasl");
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
uniPort = get_http_port(default:80);
if(!get_port_state(uniPort)){
  exit(0);
}

## GET the version from KB
uniVer = get_kb_item("www/" + uniPort + "/Uniform-Server");
if(!uniVer){
exit(0);
}

version = eregmatch(pattern:"([0-9.]+)", string:uniVer);
if(!isnull(version[1]))
{
  ## Check the Uniform Server version equal to 5.6.5
  if(version_is_less_equal(version:version[1], test_version:"5.6.5")){
    security_warning(uniPort);
  }
}
