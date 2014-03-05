##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asus_rt56u_router_mult_vuln.nasl 30088 2013-06-11 14:55:27Z June$
#
# ASUS RT56U Router Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  shell commands and obtain the sensitive information.
  Impact Level: Application";
tag_affected = "Asus RT56U version 3.0.0.4.360 and prior";


tag_insight = "The flaws are due to insufficient (or rather, a complete lack thereof) input
  sensitization leads to the injection of shell commands. It is possible to
  upload and execute a backdoor.";
tag_solution = "No solution or patch is available as of 11th June, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.asus.com/Networking/RTN56U";
tag_summary = "This host is running ASUS RT56U Router and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803715);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-11 13:49:12 +0530 (Tue, 11 Jun 2013)");
  script_name("ASUS RT56U Router Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25998");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/asus-rt56u-remote-command-injection");
  script_xref(name : "URL" , value : "http://forelsec.blogspot.in/2013/06/asus-rt56u-remote-command-injection.html");
  script_description(desc);
  script_summary("Try to read the restricted file Nologin.asp");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the device from banner
banner = get_http_banner(port: port);
if(banner && 'WWW-Authenticate: Basic realm="RT-N56U"' >!< banner){
  exit(0);
}

## Confirm the exploit by reading  content of Nologin.asp
if(http_vuln_check(port:port, url:"/Nologin.asp", pattern:">Login user IP:",
   extra_check:make_list(">You cannot Login unless logout another user first",
                         ">ASUS Wireless Router Web Manager<")))
{
  security_hole(port:port);
  exit(0);
}
