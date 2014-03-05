###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netsaro_messenger_server_sec_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# NetSaro Enterprise Messenger Server Plaintext Password Storage Vulnerability
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
tag_impact = "Successful exploitation could allow local attackers to access the
  configuration.xml file. Then can decrypt all username and password
  values and reuse them against other systems within the network.
  Impact Level: Application";
tag_affected = "NetSaro Enterprise Messenger Server version 2.0 and prior.";
tag_insight = "The flaw exists in application because it stores the username and password in
  plain text format, which allows an attacker to easily decrypt passwords used
  to authenticate to the application.";
tag_solution = "No solution or patch is available as of 04th October, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.netsaro.com/";
tag_summary = "The host is running NetSaro Enterprise Messenger Server and is prone
  to security bypass vulnerability.";

if(description)
{
  script_id(902465);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)");
  script_cve_id("CVE-2011-3692", "CVE-2011-3693");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Low");
  script_name("NetSaro Enterprise Messenger Server Plaintext Password Storage Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2011/Aug/94");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519284");
  script_xref(name : "URL" , value : "http://www.solutionary.com/index/SERT/Vuln-Disclosures/NetSaro-Enterprise-Messenger-Vuln-Password.html");

  script_description(desc);
  script_summary("Check for security bypass vulnerability in NetSaro Enterprise Messenger Server");
  script_category(ACT_GATHER_INFO);
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
include("version_func.inc");
include("http_keepalive.inc");

## Check for the default port
port = 4992;

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Send the request and receive response
sndReq = http_get(item:"/", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm the server
if("></NetSaroEnterpriseMessenger>" >< rcvRes)
{
  ## Grep for the version
  netsVer = eregmatch(pattern:'version="([0-9.]+)', string:rcvRes);
  if(netsVer[1] != NULL)
  {
    ## Check NetSaro Enterprise Messenger Server version 2.0 (2.1) and prior
    if(version_is_less_equal(version:netsVer[1], test_version:"2.1")){
      security_note(0);
    }
  }
}
