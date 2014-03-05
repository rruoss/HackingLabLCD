# OpenVAS Vulnerability Test
# $Id: http_methods.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Test HTTP dangerous methods
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2000 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "Misconfigured web servers allows remote clients to perform
dangerous HTTP methods such as PUT and DELETE. This script
checks if they are enabled and can be run";

# Check for bad permissions on a web server
#
# RFCs:
# 1945 Hypertext Transfer Protocol -- HTTP/1.0. T. Berners-Lee, R.
#      Fielding, H. Frystyk. May 1996. (Format: TXT=137582 bytes) (Status:
#      INFORMATIONAL)
# 2068 Hypertext Transfer Protocol -- HTTP/1.1. R. Fielding, J. Gettys,
#      J. Mogul, H. Frystyk, T. Berners-Lee. January 1997. (Format:
#      TXT=378114 bytes) (Obsoleted by RFC2616) (Status: PROPOSED STANDARD)
# 2616 Hypertext Transfer Protocol -- HTTP/1.1. R. Fielding, J. Gettys,
#      J. Mogul, H. Frystyk, L. Masinter, P. Leach, T. Berners-Lee. June
#      1999. (Format: TXT=422317, PS=5529857, PDF=550558 bytes) (Obsoletes
#      RFC2068) (Updated by RFC2817) (Status: DRAFT STANDARD)

if(description)
{
 script_id(10498);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_bugtraq_id(12141);
 script_xref(name:"OWASP", value:"OWASP-CM-001");
 
 name = "Test HTTP dangerous methods";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;




 script_description(desc);
 
 summary = "Verifies the access rights to the web server (PUT, DELETE)";
 
 script_summary(summary);
 # Integrist check verifies if the PUT and DELETE methods are _disabled_
 # i.e. the web server should return a 501 error instead of 403
 # With IIS, there is no way to get a 5xx error code.
 #script_add_preference(name:"Integrist test", type:"checkbox", value:"no");

 script_category(ACT_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2000 Michel Arboi");
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

#integrist = script_get_preference("Integrist test");
#if (!integrist) integrist="no";

function exists(file, port)
{
 local_var	_soc, req, r, buf;

 _soc = http_open_socket(port);
 if(!_soc)return(0);
 req = http_get(item:file, port:port);
 send(socket:_soc, data:req);
 r = recv_line(socket:_soc, length:4096);
 buf = http_recv(socket: _soc, code: r);
 close(_soc);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:r)
    && ("A quick brown fox jumps over the lazy dog" >< buf))
 {
   return(1);
 }
 else
  return(0);
}


port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded" ) ) exit(0);

soc = http_open_socket(port);
if (!soc) exit(0);

# look for Allow field
req = http_get(item: "*", port: port);
req = str_replace(string: req, find: "GET", replace: "OPTIONS", count: 1);
send(socket: soc, data: req);
r = http_recv(socket: soc);

allow = egrep(string: r, pattern: "^Allow:");
##if (!allow) allow = "Allow: PUT,DELETE";

soc = http_open_socket(port);
if (!soc) exit(0);

 for (i=1; exists(file:string("/puttest", i,".html"), port:port); i = i+1)
 {
   if(i > 20)exit(0); # we could not test this server - really strange
 } 
 name = string("/puttest",i,".html");
 #display(name, " is not installed\n");
 c = crap(length:77, data:"A quick brown fox jumps over the lazy dog");
 req = http_put(item:name, port:port, data:c);
 send(socket:soc, data:req);

 l = recv_line(socket:soc,length:1024);
 close(soc);
 #display(l);
 upload=0;
 if (exists(port:port, file:name)) {
  upload=1;
  security_hole(port:port, protocol:"tcp",
data: string("We could upload the file '",name, "' onto your web server\nThis allows an attacker to run arbitrary code on your server, or set a trojan horse\nSolution: disable this method") );
 } else {
   #if("yes" >< integrist)
    {
  if (" 401 " >< l && "PUT" >< allow) {
   #display("answer = ", l, "\n");
   security_hole(port:port, protocol:"tcp",
data:string("It seems that the PUT method is enabled on your web server\nAlthough we could not exploit this, you'd better disable it\nSolution: disable this method"));
    }
  }
 }

 
 # Leave file for next test (DELETE). Dirty...

 if (! upload) { name = NULL; }


 
if (name)
{ 
 soc = http_open_socket(port);
 if(!soc)exit(0);
 req = http_delete(item:name, port:port);
 send(socket:soc, data: req);
 l = recv_line(socket:soc, length:1024);

 if (" 200 " >< l) {
  e = exists(port:port, file:name);
}
else
 e = 1;

  if(!e)
    security_hole(port:port, protocol:"tcp",
data: string("We could DELETE the file '", name, "'on your web server\nThis allows an attacker to destroy some of your pages\nSolution: disable this method") ) ;
 } else {
  if (" 401 " >< l && " is disabled " >!< l && "DELETE" >< allow) {
   security_hole(port:port, protocol:"tcp",
data:string("It seems that the DELETE method is enabled on your web server\nAlthough we could not exploit this, you'd better disable it\nSolution: disable this method"));
 }
}
 
