###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_glfusion_mult_sql_injecton_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# glFusion Multiple SQL Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker cause SQL injection attack and
  gain sensitive information.
  Impact Level: Application";
tag_affected = "glFusion version 1.1.2 and prior.";
tag_insight = "The flaws are due to improper validation of user supplied input via
  the 'order' and 'direction' parameters to 'search.php' that allows attacker
  to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to the latest version of glFusion 1.1.8 or later,
  For updates refer to http://www.glfusion.org/filemgmt/index.php";
tag_summary = "This host is running glFusion and is prone to multiple SQL
  injection vulnerabilities.";

if(description)
{
  script_id(901111);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2009-4796");
  script_bugtraq_id(34281);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("glFusion Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34519");
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/9sg_glfusion_sql.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/502260/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of glFusion");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/", "/glFusion", "/glfusion/public_html", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('>glFusion' >< res)
  {
    ## Get glFusion Version
    ver = eregmatch(pattern:"glFusion v([0-9.]+)", string:res);
    if(ver[1]!= NULL)
    {
      ## Check for version before 1.1.2
      if(version_is_less_equal(version:ver[1], test_version:"1.1.2"))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
