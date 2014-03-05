###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netsaro_messenger_server_info_disc_vuln_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# NetSaro Enterprise Messenger Server Source Code Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod http://www.secpod.com
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
tag_impact = "Successful exploitation could allow local attackers to obtain access to the
  source code for the application and use information found to conduct further
  attacks against the application.
  Impact Level: Application";
tag_affected = "NetSaro Enterprise Messenger Server version 2.0 and prior.";
tag_insight = "The flaw exists due to error in administration console, allowing a remote
  attacker to obtain unauthenticated access to the applications source code.
  Attackers may make HTTP GET requests and append a Null Byte (%00) to allow
  download of the source code for the applications web pages.";
tag_solution = "No solution or patch is available as of 04th October, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.netsaro.com/";
tag_summary = "The host is running NetSaro Enterprise Messenger Server and is
  prone to source code disclosure vulnerability.";

if(description)
{
  script_id(902472);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-3694");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("NetSaro Enterprise Messenger Server Source Code Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104454/SERT-VDN-1012.txt");
  script_xref(name : "URL" , value : "http://www.solutionary.com/index/SERT/Vuln-Disclosures/NetSaro-Enterprise-Messenger-Source-Code.html");

  script_description(desc);
  script_summary("Check for source code disclosure vulnerability in NetSaro Enterprise Messenger Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
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
include("http_keepalive.inc");

## Check for the default port
port = 4990;

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Send the request and receive response
sndReq = http_get(item:"/", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm the server
if("<title>NetSaro Administration Console</title>" >< rcvRes)
{
  ## Construct the request with null byte
  sndReq = http_get(item:"/server-summary.nsp%00", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## Check for the source code of server-summary.nsp
  if(">System Summary</" >< rcvRes &&  ">Product Information</" >< rcvRes){
      security_warning(0);
  }
}
