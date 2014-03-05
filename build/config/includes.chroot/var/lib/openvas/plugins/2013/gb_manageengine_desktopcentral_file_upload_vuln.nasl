###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_desktopcentral_file_upload_vuln.nasl 71 2013-11-21 12:11:40Z veerendragg $
#
# ManageEngine DesktopCentral Arbitrary File Upload Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(803777);
  script_version("$Revision: 71 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-11-21 13:11:40 +0100 (Thu, 21 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-20 12:28:14 +0530 (Wed, 20 Nov 2013)");
  script_name("ManageEngine DesktopCentral Arbitrary File Upload Vulnerability");

  tag_summary =
"This host is running ManageEngine DesktopCentral and is prone to arbitrary
file upload vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP POST request and check whether it
is able to create the file or not.";

  tag_insight =
"The flaw in the AgentLogUploadServlet. This servlet takes input from HTTP
POST and constructs an output file on the server without performing any
sanitisation or even checking if the caller is authenticated.";

  tag_impact =
"Successful exploitation will allow an attacker to gain arbitrary code
execution on the server.

Impact Level: System/Application";

  tag_affected =
"ManageEngine DesktopCentral 8.0.0 (build 80293 and below)";

  tag_solution =
"Apply the patch supplied by the vendor (Patch 80293),
http://www.manageengine.com/products/desktop-central";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/29674");
  script_xref(name : "URL" , value : "http://security-assessment.com/files/documents/advisory/DesktopCentral%20Arbitrary%20File%20Upload.pdf");
  script_summary("Check if ManageEngine DesktopCentral is vulnerable to file upload");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8020);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
url = "";
mecPort = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
mecPort = get_http_port(default:8020);
if(!mecPort){
  mecPort = 8020;
}

## Check the port status
if(!get_port_state(mecPort)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

sndReq = http_get(item:"/configurations.do", port:mecPort);
rcvRes = http_keepalive_send_recv(port:mecPort, data:sndReq, bodyonly:TRUE);

## confirm the Application
if(rcvRes && '>ManageEngine Desktop Central' >< rcvRes && 'DesktopCentra' >< rcvRes)
{
  postdata ="This file is uploaded by OpenVAS scanner for vulnerability testing";
  url = "/agentLogUploader?computerName=DesktopCentral&domainName=webapps&custom" +
        "erId=1&filename=ov-file-upload-test.jsp";

  ## Construct the POST request
  sndReq = string("POST ", url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Content-Type: text/html;\r\n",
                  "Content-Length: ", strlen(postdata), "\r\n",
                  "\r\n", postdata);

  ## Send post request and Receive the response
  rcvRes = http_send_recv(port:mecPort, data:sndReq);

  ## confirm the exploit
  if(rcvRes && rcvRes =~ "HTTP/1\.[0-9]+ 200" && "X-dc-header: yes" >< rcvRes)
  {
      desc = desc + '\n\nThe scanner was able to upload a file ' +
             'ov-file-upload-test.jsp. Please remove this file.';
      security_hole(port:mecPort, data:desc);
      exit(0);
  }
}
