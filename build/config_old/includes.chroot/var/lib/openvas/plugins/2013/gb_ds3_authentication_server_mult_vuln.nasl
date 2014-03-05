##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ds3_authentication_server_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# DS3 Authentication Server Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  commands and obtain the sensitive information.
  Impact Level: Application";
tag_affected = "DS3 Authentication Server";


tag_insight = "The flaws are due to,
  - The TestTelnetConnection.jsp does not validate the user input, allowing
    an attacker to execute arbitrary commands in the server side with the
    privileges of asadmin user.
  - TestDRConnection.jsp, shows the file path in the error messages, this is
    considered a minor information leak.
  - Without being authenticated, any user is able to manipulate the message
    of the default error page, helping him to develop social engineering
    attacks.";
tag_solution = "No solution or patch is available as of 04th June, 2013. Information
  regarding this issue will be updated once the solution details are available.
  http://ds3global.com/index.php/en/ds3-authentication-server/ds3-authentication-server";
tag_summary = "This host is running DS3 Authentication Server and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803710);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-04 13:59:02 +0530 (Tue, 04 Jun 2013)");
  script_name("DS3 Authentication Server Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/526784/30/0/threaded");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121862/ds3authserv-exec.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/ds3-authentication-server-command-execution");

  script_description(desc);
  script_summary("Try to read the restricted file ErrorViewer.jsp");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("openvas-https.inc");

## Variable Initialization
req = "";
res = "";
host = "";
port = "";

## Get Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get Host Name
host = get_host_name();
if(!host){
  exit(0);
}

## Construct https request
req = string("GET /ServerAdmin/UserLogin.jsp HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");
res = https_req_get(port:port, request:req);

## Confirm the application before trying exploit
if(res && res =~ "HTTP/1.. 200 OK" && "Server: DS3-AuthServer" >< res)
{
  ## Construct attack request
  url = '/ServerAdmin/ErrorViewer.jsp?message=Message';

  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n\r\n");
  res = https_req_get(port:port, request:req);

  ## Confirm exploit worked by checking the response
  if(res && res =~ "HTTP/1.. 200 OK" &&
     ">Error Page<" >< res && ">Error Message:" >< res)
  {
    security_hole(port);
    exit(0);
  }
}
