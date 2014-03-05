###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jpgraph_mult_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# JpGraph Multiple Cross-Site Scripting Vulnerabilities
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
tag_solution = "Apply patches from below link,
  http://www.securityfocus.com/archive/1/archive/1/508586/100/0/threaded

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an
  affected site and it result in XSS attack.
  Impact Level: Application.";
tag_affected = "JpGraph version 3.0.6 and prior on all running platform.";
tag_insight = "The flaw is due to the 'GetURLArguments()' function in 'jpgraph.php' not
  properly sanitising HTTP POST and GET parameter keys.";
tag_summary = "The host is running JpGraph and is prone to multiple Cross-Site
  Scripting vulnerabilities.";

if(description)
{
  script_id(800414);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4422");
  script_bugtraq_id(37483);
  script_name("JpGraph Multiple Cross-Site Scripting Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://osvdb.org/61268");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37832");

  script_description(desc);
  script_summary("Check for the version of JpGraph");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_jpgraph_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

jgphPort = get_http_port(default:80);
if(!jgphPort){
  exit(0);
}

jgphVer = get_kb_item("www/" + jgphPort + "/JpGraph");
if(!jgphVer){
  exit(0);
}

jgphVer = eregmatch(pattern:"^(.+) under (/.*)$", string:jgphVer);
if(!safe_checks() && jgphVer[2] != NULL)
{
  request = http_get(item:jgphVer[2] + "/../src/Examples/csim_in_html_ex1.php?'" +
                         "/><script>alert('OpenVAS-XSS')</script>=arbitrary",
                       port:jgphPort);
  response = http_send_recv(port:jgphPort, data:request);
  if("\'OpenVAS-XSS\'" >< response)
  {
    security_warning(jgphPort);
    exit(0);
  }
}

if(jgphVer[1] != NULL)
{
  if(version_is_less_equal(version:jgphVer[1], test_version:"3.0.6")){
    security_warning(jgphPort);
  }
}
