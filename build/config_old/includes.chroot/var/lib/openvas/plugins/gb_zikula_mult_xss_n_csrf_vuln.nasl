##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zikula_mult_xss_n_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Zikula Multiple XSS and CSRF Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-02-16
#      - Added CVE CVE-2010-4729 and updated description
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
tag_impact = "Successful exploitation will allow remote attackers to compromise the
  application, disclosure or modification of sensitive data, execute arbitrary
  HTML and script and conduct cross-site request forgery (CSRF) attacks.
  Impact Level: Application.";
tag_affected = "Zikula version prior to 1.2.3";

tag_insight = "- Input passed to the 'lang' parameter and to the 'func' parameter in the
    'index.php' is not properly sanitised before being returned to the user.
  - Failure in the 'users' module to properly verify the source of HTTP request.
  - Error in 'authid protection' mechanism for lostpassword form and mailpasswd
    processing, which makes it easier for remote attackers to generate a flood of
    password requests.";
tag_solution = "Upgrade to the Zikula version 1.2.3 or later
  For updates refer to http://zikula.org/";
tag_summary = "This host is running Zikula and is prone to multiple cross-site
  scripting and cross-site request forgery vulnerabilities.";

if(description)
{
  script_id(800773);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1732", "CVE-2010-1724", "CVE-2010-4729");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Zikula Multiple XSS and CSRF Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39614");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58224");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/510988/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_vulnerability_in_zikula_application_framework.html");

  script_description(desc);
  script_summary("Check for the version of Zikula");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
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

zkPort = get_http_port(default:80);
if(!get_port_state(zkPort)){
  exit(0);
}

## Get Zikula version from KB
zkVer = get_kb_item("www/"+ zkPort + "/zikula");
if(!zkVer){
 exit(0);
}

zkVer = eregmatch(pattern:"^(.+) under (/.*)$", string:zkVer);

## Check for the Zikula version
if(zkVer[1] != NULL)
{
  if(version_is_less(version:zkVer[1], test_version:"1.2.3")){
    security_hole(zkPort);
  }
}
