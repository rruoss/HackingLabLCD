##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_directory_source_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpDirectorySource Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML or
  execute arbitrary SQL commands in the context of an affected site.
  Impact Level: Application.";
tag_affected = "phpDirectorySource version 1.x";

tag_insight = "- Input passed to 'search.php' through 'st' parameter is not properly
    sanitised before being returned to the user and before being used in SQL
    queries.";
tag_solution = "No solution or patch is available as of 12th March 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.phpdirectorysource.com/";
tag_summary = "This host is running phpDirectorySource and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(800738);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(35760);
  script_cve_id("CVE-2009-4680","CVE-2009-4681");
  script_name("phpDirectorySource Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35941");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9226");

  script_description(desc);
  script_summary("Check through the attack string on phpDirectorySource");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
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

## Get HTTP Port
phpPort = get_http_port(default:80);
if(!phpPort){
  exit(0);
}

foreach dir (make_list("/pds", "/" , cgi_dirs()))
{
  ## Send and Recieve request
  sndReq = http_get(item:string(dir, "/index.php"), port:phpPort);
  rcvRes = http_send_recv(port:phpPort, data:sndReq);

  ## Confirm application is phpDirectorySource
  if("phpDirectorySource" >< rcvRes)
  {
    ## Try XSS attack on phpDirectorySource application
    sndReq = http_get(item:string(dir, '/search.php?sa=site&sk=a&nl=11&st=">'+
            '<script>alert("OpenVASExploitTesting");</script>'), port:phpPort);
    rcvRes = http_send_recv(port:phpPort, data:sndReq);
    if(("OpenVASExploitTesting" >< rcvRes))
    {
      security_hole(phpPort);
      exit(0);
    }
  }
}
