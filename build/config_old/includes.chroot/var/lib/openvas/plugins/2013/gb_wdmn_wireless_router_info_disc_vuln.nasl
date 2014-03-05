###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wdmn_wireless_router_info_disc_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Western Digital My Net Devices Information Disclosure Vulnerability
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
tag_impact = "
  Impact Level: Application";

if(description)
{
  script_id(803731);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-5006");
  script_bugtraq_id(61361);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-05 16:18:11 +0530 (Mon, 05 Aug 2013)");
  script_name("Western Digital My Net Devices Information Disclosure Vulnerability");

  tag_summary =
"This host is running Western Digital My Net Router and is prone to information
disclosure vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP request and check whether it is able to read the
password or not.";

  tag_insight =
"The issue is due to the device storing the admin password in clear text in the
main_internet.php source code page as the value for 'var pass'.";

  tag_impact =
"Successful exploitation will allow attacker to gain access to credential
information.";

tag_affected =
"Western Digital My Net N600 1.03, 1.04,
Western Digital My Net N750 1.03, 1.04,
Western Digital My Net N900 1.05, 1.06 and
Western Digital My Net N900C 1.05, 1.06";

tag_solution =
"No solution or patch is available as of 05th August, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.wdc.com/en/";

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
  script_xref(name : "URL" , value : "http://www.osvdb.org/95519");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Aug/10");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/85903");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/527433");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2013-07/0146.html");
  script_summary("Check if Western Digital My Net is vulnerable to password disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";
req = "";
res = "";
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
if(banner && banner =~ "MyNetN[6|7|9]")
{
  ## Send and Receive the response
  req = http_get(item: "/main_internet.php", port:port);
  res = http_send_recv(port:port,data:req);

  ## Confirm the exploit
  if(">WESTERN DIGITAL" >< res && "WIRELESS ROUTER" >< res
     && res =~ 'var pass=".*";' )
  {
    security_warning(port);
    exit(0);
  }
}
