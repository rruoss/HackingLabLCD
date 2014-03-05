###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cscart_sql_injection_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# CS-Cart 'product_id' Parameter SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "CS-Cart version 2.0.0 Beta 3";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'product_id' parameter to index.php that allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to CS-Cart version 2.0.15 or later,
  For updates refer to http://www.cs-cart.com/";
tag_summary = "The host is running CS-Cart and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(901123);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-16 08:26:33 +0200 (Wed, 16 Jun 2010)");
  script_cve_id("CVE-2009-4891");
  script_bugtraq_id(34048);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("CS-Cart 'product_id' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49154");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8184");

  script_description(desc);
  script_summary("Check for the version of CS-Cart");
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

foreach dir (make_list("/", "/cscart", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if("<title>CS-Cart. Powerful PHP shopping cart software</title>" >< res)
  {
    ## Get log file
    req = http_get(item:string(dir,"/changelog.txt"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    ## Get Version from log file
    ver = eregmatch(pattern:"[v|V]ersion ([0-9.]+)(.?([a-zA-Z0-9]+))?",
                                                                 string:res);
    if(ver[1] != NULL)
    {
      if(ver[3] != NULL){
        csVer = ver[1] + "." + ver[3];
      }
      else{
        csVer = ver[1];
      }
      
      ## Check for CS-Cart  version 2.0.0 Beta 3
      if(version_is_equal(version:csVer, test_version:"2.0.0.beta3")) {
        security_hole(port);
        exit(0);
      }
    }
  }
}

