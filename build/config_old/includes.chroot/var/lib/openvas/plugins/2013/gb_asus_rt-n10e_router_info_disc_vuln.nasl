##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asus_rt-n10e_router_info_disc_vuln.nasl 32348 2013-10-10 14:55:27Z oct$
#
# ASUS RT-N10E Wireless Router Information Disclosure Vulnerability
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

if(description)
{
  script_id(803769);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3610");
  script_bugtraq_id(62850);
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-10 13:46:03 +0530 (Thu, 10 Oct 2013)");
  script_name("ASUS RT-N10E Wireless Router Information Disclosure Vulnerability");

  tag_summary =
 "This host is running ASUS RT-N10E Wireless Router and is prone to information
disclosure vulnerability.";

  tag_vuldetect =
"Send direct HTTP GET request and check it is possible to read the password
and other informations or not.";

  tag_insight =
"The flaw is due to the device not properly restricting access to the
'/qis/QIS_finish.htm' page.";

  tag_impact =
"Successful exploitation will allow remote attacker to disclose certain
sensitive information.

Impact Level: Application";

  tag_affected =
"ASUS Wireless-N150 Router RT-N10E firmware versions 2.0.0.24 and earlier.";

  tag_solution =
"Upgrade to ASUS Wireless-N150 Router RT-N10E firmware 2.0.0.25 or later,
For updates refer to http://www.asus.com/Networking/RTN10E/#support_Download";

 desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/98118");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55159");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/984366");
  script_summary("Try to read the restricted file '/qis/QIS_finish.htm'");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}


## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the device from banner
banner = get_http_banner(port: port);
if(banner && 'WWW-Authenticate: Basic realm="RT-N10E"' >!< banner){
  exit(0);
}

## Confirm the exploit by reading  content of QIS_finish.htm
if(http_vuln_check(port:port, url:"/qis/QIS_finish.htm",
   pattern:"ASUS Wireless Router",
   extra_check:make_list("password_item",
   "account_item", "#wanip_item")))
{
  security_hole(port:port);
  exit(0);
}
