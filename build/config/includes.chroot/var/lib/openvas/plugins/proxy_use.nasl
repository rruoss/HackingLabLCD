###############################################################################
# OpenVAS Vulnerability Test
# $Id: proxy_use.nasl 43 2013-11-04 19:51:40Z jan $
#
# HTTP Proxy Server Detection
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
tag_summary = "A HTTP proxy server is running at this Host and accepts
   unauthenticated requests from the OpenVAS Scanner.

   An open proxy is a proxy server that is accessible by any Internet
   user. Generally, a proxy server allows users within a network group
   to store and forward Internet services such as DNS or web pages to
   reduce and control the bandwidth used by the group. With an open
   proxy, however, any user on the Internet is able to use this
   forwarding service.";

tag_solution = "Limit access to the proxy to valid users and/or valid hosts.";

if(description)
{
 script_id(100083);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-28 19:13:00 +0100 (Sat, 28 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "HTTP Proxy Server Detection";
 script_name(name);
 
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "HTTP Proxy Server Detection";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 family = "Firewalls";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/http_proxy", 3128, 8080, 6588, 8000);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/http_proxy"));
port_list = make_list("3128","8080","6588","8000","80");

foreach add_port (port_list) {
 if(get_port_state(add_port)) {
   ports = add_port_in_list(list:ports, port:add_port);
 }
}

if(!ports)exit(0);

foreach port (ports) {
 
 url = 'http://www.openvas.org/openvas-proxy-test';
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 
 if( buf == NULL )continue;

 if ( "%%openvas-proxy-test%%" >< buf ) {

  set_kb_item(name:"Proxy/usage", value:TRUE);
  set_kb_item(name:"Services/http_proxy", value:port);

  if(egrep(pattern: "squid", string: buf, ICASE:TRUE)) {
   if(!get_kb_item("www/squid")) { 
    	set_kb_item(name:"www/squid", value:TRUE);
   } 
  }  

  if(VIA = egrep(pattern: "^Via:.*$", string: buf)) {
   if(VIA = eregmatch(pattern: "^Via: (.*)$", string: VIA)) {
    set_kb_item(name:string("Proxy/" + port  + "/via"), value: chomp(VIA[1])); 
   }
  }

  security_note(port:port);

 }
}

exit(0);
