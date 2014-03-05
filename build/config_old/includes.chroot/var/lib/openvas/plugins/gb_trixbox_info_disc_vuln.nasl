###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trixbox_info_disc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Trixbox Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows attackers to obtain valid usernames, which
  may aid them in brute-force password cracking or other attacks.
  Impact Level: Application";
tag_affected = "Trixbox version 2.8.0.4 and prior.";
tag_insight = "The flaw is due to Trixbox returning valid usernames via a http GET
  request to a Flash Operator Panel(FOP) file.";
tag_solution = "No solution or patch is available as of 07th July, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://fonality.com/trixbox/downloads";
tag_summary = "The host is running Trixbox and is prone to information disclosure
  vulnerability.";

if(description)
{
  script_id(802210);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_bugtraq_id(48503);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Trixbox Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102627/trixboxfop-enumerate.txt");

  script_description(desc);
  script_summary("Determine if Trixbox is vulnerable to Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Send and Recieve the response
req = http_get(item:"/user/index.php",  port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Confirm the application
if("<TITLE>trixbox - User Mode</TITLE>" >< res)
{
  ## Try to access variables.txt file
  req = http_get(item:"/panel/variables.txt", port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Check for the file status
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
    ("Content-Type: text/plain" >< res) && ("Asterisk" >< res)) {
    security_warning(port);
  }
}
