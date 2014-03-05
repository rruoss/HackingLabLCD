##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_p1_wimax_modem_default_credentials_ua_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# P1 WiMAX Modem Default Credentials Unauthorized Access Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to login with default
  credentials and gain access to modem.
  Impact Level: Application";
tag_affected = "P1 WiMAX Modem";

tag_insight = "The flaw is due to the default configuration of the modem allows
  anyone to access port 80 from the internet and modem is using the same
  default login with 'admin' as the username and 'admin123' as the password.";
tag_solution = "No solution or patch is available as of 11th October, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.p1.com.my/";
tag_summary = "This host has P1 WiMAX Modem and is prone default credentials
  unauthorized access vulnerability.";

if(description)
{
  script_id(802476);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-15 15:53:36 +0530 (Mon, 15 Oct 2012)");
  script_name("P1 WiMAX Modem Default Credentials Unauthorized Access Vulnerability");
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
  script_xref(name : "URL" , value : "http://pastebin.com/pkuNfSJF");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Oct/99");

  script_description(desc);
  script_summary("Checks if login with default credentials is possible");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("http_keepalive.inc");

## Variable Initialization
req = "";
res = "";
host = "";
port = "";

## Check the default port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Host Name
host = get_host_name();
if(!host){
  exit(0);
}

req = http_get(item:"/login.php", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

## Confirm the application
if(res =~ "HTTP/[0-9]\.[0-9] 200 .*" && "Server: lighttpd" >< res
   && "UI_ADMIN_USERNAME" >< res && "UI_ADMIN_PASSWORD" >< res)
{
  postdata = "UI_ADMIN_USERNAME=admin&UI_ADMIN_PASSWORD=admin123";
  req = string("POST /ajax.cgi?action=login HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);

  res = http_keepalive_send_recv(port:port, data:req);

  ## confirm the login success
  if( res =~ "HTTP/[0-9]\.[0-9] 200 .*" &&
     "location.href='index.php?sid=" >< res &&
     "Login Fail:" >!< res){
     security_hole(port:port);
  }
}
