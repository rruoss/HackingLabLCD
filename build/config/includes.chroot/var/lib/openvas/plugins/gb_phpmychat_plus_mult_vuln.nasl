###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmychat_plus_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# phpMyChat Plus Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack,
  gain sensitive information about the database used by the web application or
  can cause arbitrary code execution inside the context of the web application.
  Impact Level: Application";
tag_affected = "phpMyChat Plus version 1.93";
tag_insight = "The flaws are due to:
  - Improper sanitization of user supplied input through the 'CookieUsername'
    and 'CookieStatus' parameter in Cookie.
  - Improper sanitization of user supplied input through the 'pmc_password'
    parameter in a printable action to avatar.php.";
tag_solution = "No solution or patch is available as of 06th May 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/phpmychat/";
tag_summary = "This host is running MyChat Plus and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801936);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("MyChat Plus Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17213/");
  script_xref(name : "URL" , value : "http://www.rxtx.nl/webapps-phpmychat-plus-1-93-multiple-vulnerabilities/");
  script_xref(name : "URL" , value : "http://www.l33thackers.com/Thread-webapps-phpMyChat-Plus-1-93-Multiple-Vulnerabilities");

  script_description(desc);
  script_summary("Check if phpMyChat Plus is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/plus", "/phpMyChat", "/"))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("<TITLE>My WonderfulWideWeb Chat - phpMyChat-Plus</TITLE>" >< res)
  {
    req = http_get(item:string(dir, '/avatar.php?pmc_password="' +
                   '><script>alert("XSS-TEST")</script>'), port:port);

    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if('<script>alert("XSS-TEST")</script>' >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
