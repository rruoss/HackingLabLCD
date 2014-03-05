###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rabbit_wiki_title_param_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# RabbitWiki 'title' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_affected = "RabbitWiki";
tag_insight = "The flaw is due to an improper validation of user-supplied input to
  the 'title' parameter in 'index.php', which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of
  an affected site.";
tag_solution = "No solution or patch is available as of 13th February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.rustyspigot.com/webmasters/s/RabbitWiki/";
tag_summary = "This host is running RabbitWiki and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(802608);
  script_bugtraq_id(51971);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-13 15:15:15 +0530 (Mon, 13 Feb 2012)");
  script_name("RabbitWiki 'title' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51971");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109628/rabbitwiki-xss.txt");
  script_xref(name : "URL" , value : "http://st2tea.blogspot.in/2012/02/rabbitwiki-cross-site-scripting.html");

  script_description(desc);
  script_summary("Check if RabbitWiki is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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

## Variable Initialization

dir = "";
url = "";
req = "";
res = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(! port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/RabbitWiki", "/wiki", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: dir + "/index.php", port: port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application before trying exploit
  if(!isnull(res) && '>RabbitWiki<' >< res)
  {
    ## Construct Attack Request
    url = dir + "/index.php?title=<script>alert(/openvas-xss-test/)</script>";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
       pattern:"<script>alert\(/openvas-xss-test/\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
