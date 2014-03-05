##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zyxel_zywall_web_config_auth_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# ZyXEL ZyWALL Web Configurator Authentication Bypass Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to gain administrative access,
  circumventing existing authentication mechanisms.
  Impact Level: Application";
tag_affected = "ZyXEL ZyWALL";


tag_insight = "By default, ZyXEL ZyWALL installs with default user credentials
  (username/password combination). The web configurator account has a
  password of '1234', which is publicly known and documented. This allows
  remote attackers to trivially access the program or system and gain
  privileged access.";
tag_solution = "No solution or patch is available as of 14th May, 2013. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.zyxel.com/";
tag_summary = "This host is running ZyXEL ZyWALL Web Configurator and prone to
  authentication bypass vulnerability.";

if(description)
{
  script_id(803199);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-14 17:25:01 +0530 (Tue, 14 May 2013)");
  script_name("ZyXEL ZyWALL Web Configurator Authentication Bypass Vulnerability");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/93277");
  script_xref(name : "URL" , value : " http://dariusfreamon.wordpress.com/2013/05/12/sunday-shodan-defaults/");
  script_summary("Try to login with the default user credentials");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Privilege escalation");
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
port = "";
req = "";
res = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the banner and confirm the application
banner = get_http_banner(port:port);
if("Server: RomPager" >!< banner){
  exit(0);
}

url = '/Forms/rpAuth_1';

##Construct post data
postData = "LoginPassword=ZyXEL+ZyWALL+Series&hiddenPassword=ee11cbb19052" +
           "e40b07aac0ca060c23ee&Prestige_Login=Login";

##Construct the request string
req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData);

## Send request and receive the response
res = http_keepalive_send_recv(port:port, data:req);
if(res =~ "HTTP/1.. 303" && res =~ "Location:.*rpSys.html")
{
  security_hole(port);
  exit(0);
}
