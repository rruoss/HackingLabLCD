###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_web_login_xss_vuln.nasl 71 2013-11-21 12:11:40Z veerendragg $
#
# JunOS Web Login Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803775";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 71 $");
  script_bugtraq_id(63656);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-11-21 13:11:40 +0100 (Thu, 21 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-18 13:23:22 +0530 (Mon, 18 Nov 2013)");
  script_name("JunOS Web Login Cross Site Scripting Vulnerability");

  tag_summary =
"This host is running JunOS and is prone to cross-site scripting
vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it
is able to read the cookie or not.";

  tag_insight =
"The flaw is due to an improper validation of user-supplied input via the
'error' parameter to the 'index.php', which allows the attackers to execute
arbitrary HTML and script code in a user's browser session in the context
of an affected site.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
HTML and script code in a user's browser session in the context of an affected
site.

Impact Level: Application";

  tag_affected =
"JunOS version to 11.4 and prior (probably 12.1 and 12.3 vulnerable)";

  tag_solution =
"No solution available as of 18th November, 2013. Information regarding this
issue will be updated once the solution details are available.
For updates refer to http://www.juniper.net/us/en";

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
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/63656");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/junos-114-cross-site-scripting");
  script_summary("Check if JunOS is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
res = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80 ;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

banner = get_http_banner(port:port);
if("Server: Mbedthis-Appweb/" >!< banner){
  exit(0);
}

## Send and Recieve the response
req = http_get(item:"/index.php", port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Confirm the application
if(res && "Juniper Networks, Inc" >< res && ">Log In" >< res)
{
  ## Construct the attack request
  url = '/index.php?name=Your_Account&error=1"><script>' +
        'alert(document.cookie)<%2Fscript>&uname=bGF';

  ## Confirm the exploit
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"><script>alert\(document.cookie\)</script>",
     extra_check: make_list(">Log In", "Juniper Networks")))
  {
    security_warning(port);
    exit(0);
  }
}
