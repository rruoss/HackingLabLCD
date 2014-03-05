###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jboss_application_server_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# JBoss Application Server Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to get the  all services
  with their paths on the server and get the sensitive information.
  Impact Level: Application";
tag_affected = "JBoss Application Server 5.0 and prior.";
tag_insight = "Multiple flaws are due to,
  - Status page is publicly accessible. Which leads to leakage of logs of last
    connections and (in second case) leakage of all services (with their paths)
    on the server.
  - There is no protection against Brute Force attacks at these resources and
    other private resources with BF vulnerability. The list of all resources of
    concrete server can be found at page status?full=true.";
tag_solution = "No solution or patch is available as of 16th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer tohttp://www.jboss.org/jbossas/downloads/";
tag_summary = "The host is running JBoss Application Server and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801987);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("JBoss Application Server Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Sep/139");

  script_description(desc);
  script_summary("Determine if JBoss Application Server is prone multiple vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
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

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the Server
banner = get_http_banner(port: port);
if("JBoss" >!< banner){
  exit(0);
}

## Send and Receive the response
req = http_get(item: "/", port:port);
res = http_keepalive_send_recv(port:port,data:req);

## Confirm the Server
if('>JBoss Web Console</' >< res && 'Welcome to JBoss' >< res)
{
  ## construct the attack request
  req = http_get(item: "/status?full=true", port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the exploit
  if('Application list' >< res && 'WebCCReports' >< res &&
     'PortComponentLinkServlet' >< res){
   security_hole(port:port);
  }
}
