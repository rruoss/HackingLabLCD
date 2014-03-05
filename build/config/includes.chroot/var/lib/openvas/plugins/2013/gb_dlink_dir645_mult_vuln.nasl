###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir645_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# D-Link DIR-645 Router Multiple Vulnerabilities
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
  script_id(803730);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-05 15:17:38 +0530 (Mon, 05 Aug 2013)");
  script_name("D-Link DIR-645 Router Multiple Vulnerabilities");

  tag_summary =
"This host is running D-Link DIR-645 Router and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP request and check whether it is able to read
the cookie or not.";

  tag_insight =
"Multiple flaws are due to,
 - Buffer overflow in post_login.xml, hedwig.cgi and authentication.cgi
   When handling specially crafted requests.
 - Input passed to the 'deviceid' parameter in bind.php, 'RESULT' parameter
   in info.php and 'receiver' parameter in bsc_sms_send.php is not properly
   sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attacker to cause denial of service or
execute arbitrary HTML and script code in a user's browser session in context
of an affected website.";

tag_affected = "D-Link DIR-645 firmware version 1.04 and prior";

tag_solution = "No solution or patch is available as of 5th, August 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.dlink.com/ca/en/home-solutions/connect/routers/dir-645-wireless-n-home-router-1000";

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
  script_xref(name : "URL" , value : "http://www.osvdb.org/95910");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Aug/17");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27283");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Aug/17");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122659");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/527705");
  script_xref(name : "URL" , value : "http://roberto.greyhats.it/advisories/20130801-dlink-dir645.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/hardware/d-link-dir-645-103b08-multiple-vulnerabilities");
  script_summary("Check if D-Link DIR-645 is vulnerable to XSS");
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
if(banner && "DIR-645" >!< banner){
  exit(0);
}

## Send and Receive the response
req = http_get(item: "/", port:port);
res = http_send_recv(port:port,data:req);

## Confirm the device from response
if(">D-LINK SYSTEMS" >< res && ">DIR-645<" >< res)
{
  url = '/parentalcontrols/bind.php?deviceid="><script>alert' +
        '(document.cookie)</script><';

  ## Check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
                     pattern:"><script>alert\(document.cookie\)</script><",
                     extra_check:make_list("OpenDNS", "overriteDeviceID")))
  {
    security_hole(port);
    exit(0);
  }
}
