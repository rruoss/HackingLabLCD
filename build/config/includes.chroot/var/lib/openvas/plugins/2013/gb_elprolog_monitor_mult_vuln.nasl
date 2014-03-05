###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elprolog_monitor_mult_vuln.nasl 33 2013-10-31 15:16:09Z veerendragg $
#
# Elprolog Monitor WebAccess Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804113";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 33 $");
  script_bugtraq_id(62631);
  script_tag(name:"cvss_base", value:"6.7");
  script_tag(name:"cvss_base_vetor", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-31 16:16:09 +0100 (Do, 31. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-22 12:55:00 +0530 (Tue, 22 Oct 2013)");
  script_name("Elprolog Monitor WebAccess Multiple Vulnerabilities");

  tag_summary =
"This host is running Elprolog Monitor WebAccess and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it
is able to read the cookie or not.";

  tag_insight =
"Input passed via the 'data' parameter to sensorview.php and via the 'name'
parameter to strend.php is not properly sanitised before being returned to
the user.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute/inject own
SQL commands in the vulnerable web-application database management system
and force the client side browser requests with manipulated web application
context or cross site links.

Impact Level: Application";

  tag_affected =
"Elprolog Monitor Webaccess 2.1, Other versions may also be affected.";

  tag_solution =
"No solution available as of October 31, 2013. Information regarding this
issue will be updated once the solution details are available.
For updates refer to http://www.elprolog.com";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/62631");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123496");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/elprolog-monitor-webaccess-21-xss-sql-injection");
  script_summary("Check if Elprolog Monitor Webaccess is vulnerable to cross site scripting and SQL injection attacks");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/elpro-demo", "/webaccess", cgi_dirs()))
{
   req = http_get(item:string("/sensorview.php"),  port: http_port);
   res = http_keepalive_send_recv(port:http_port, data:req);

   ## confirm the Application
   if(res && ">elproLOG MONITOR-WebAccess<" >< res)
   {

     ## Construct Attack Request
     url = dir + '/sensorview.php?data=ECOLOG-NET Testing' +
           '-<script>alert(document.cookie);</script>';

     ## Check the response to confirm vulnerability
     if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\);</script>" ,
       extra_check:"ECOLOG-NET"))
    {
      security_hole(http_port);
      exit(0);
    }
  }
}
