###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dsl_router_mult_auth_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# D-Link Dsl Router Multiple Authentication Bypass Vulnerabilities
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

tag_affected = "D-Link Dsl Router BZ_1.06";
tag_insight = "The web interface of Dsl Router routers expose several pages accessible
  with no authentication. These pages can be abused to access sensitive
  information concerning the device configuration, including the clear-text
  password for the administrative user.";
tag_solution = "No solution or patch is available as of 21st May, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.dlink.com/ca/en/home-solutions/connect/routers";
tag_summary = "This host is running D-Link Dsl Router and is prone to multiple
  authentication bypass vulnerabilities.";

if(description)
{
  script_id(803700);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-21 12:05:19 +0530 (Tue, 21 May 2013)");
  script_name("D-Link Dsl Router Multiple Authentication Bypass Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/20789");
  script_xref(name : "URL" , value : "http://w00t.pro/2013/05/19/17033");
  script_xref(name : "URL" , value : "http://www.allinfosec.com/2013/05/19/web-applications-dsl-router-d-link-bz_1-06-multiple-vulnerabilities");

  script_description(desc);
  script_summary("Read the content of the configuration file password.cgi");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the device from banner
banner = get_http_banner(port: port);
if(banner && 'WWW-Authenticate: Basic realm="DSL Router"' >!< banner){
  exit(0);
}

## Confirm the exploit by reading  content of password.cgi
if(http_vuln_check(port:port, url:"/password.cgi", pattern:"pwdAdmin = '.*",
   extra_check:make_list("pwdUser = '", ">Access Control -- Passwords<",
                         "Access to your DSL router")))
{
  security_warning(port:port);
  exit(0);
}
