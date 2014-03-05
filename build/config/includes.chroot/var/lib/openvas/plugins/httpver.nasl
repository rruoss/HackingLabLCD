###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpver.nasl 43 2013-11-04 19:51:40Z jan $
#
# Detection of HTTP-Version 
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
tag_summary = "Check the HTTP-Version";

if (description)
{
 script_id(100034);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 desc = "
 Summary:
 " + tag_summary;

 script_name("HTTP-Version Detection");  

 script_description(desc);
 script_summary("Check the HTTP-Version");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

  soc = http_open_socket(port);
  if(!soc)exit(0);

  req = string("GET / HTTP/1.1\r\n",
	       "Host: ", get_host_name(), ":", port, "\r\n",
	       "Mozilla/5.0 (OpenVAS; U; Linux i686; de; rv:1.9.0.3) Gecko/2008092416 Firefox/3.0.3\r\n",
	       "Accept: */*\r\n",
	       "Connection: close\r\n",
	      "\r\n"
	      ); 
  send(socket:soc, data:req);
  buf = http_recv_headers2(socket: soc);
  close(soc);
  if( buf == NULL ) exit(0);

  if( buf =~ "HTTP/1.1 20[0-6]" || buf =~ "HTTP/1.1 30[0-7]" || buf =~ "HTTP/1.1 40[13]") {
 
    set_kb_item(name:string("http/", port), value:string("11"));
    exit(0);
 
  } 

  else if (buf =~ "HTTP/1.0 20[0-6]" || buf =~ "HTTP/1.0 30[0-7]" || buf =~ "HTTP/1.0 40[13]") {

    set_kb_item(name:string("http/", port), value:string("10"));
    exit(0);

  }

  else if (buf =~ "HTTP/1\.[0-1] 50[0-4]") {

    set_kb_item(name: "Services/www/" + port + "/broken/", value:TRUE);
    set_kb_item(name: "Services/www/" + port + "/broken/reason", value:string("50x"));
    exit(0);
   

  }

  else {

   soc = http_open_socket(port);
   if(!soc)exit(0);
   req = string("GET / HTTP/1.0\r\n",
                "\r\n"
               );
   send(socket:soc, data:req);
   buf = http_recv_headers2(socket: soc);
   if( buf == NULL ) exit(0);
   close(soc); 

   if( buf =~ "HTTP/1.0 20[0-6]" || buf =~ "HTTP/1.0 30[0-7]" || buf =~ "HTTP/1.0 40[13]") {
  
    set_kb_item(name:string("http/", port), value:string("10"));
    exit(0);
    
   } else if( buf =~ "HTTP/1\.[0-1] 50[0-9]" ) {

      set_kb_item(name: "Services/www/" + port + "/broken/", value:TRUE);
      set_kb_item(name: "Services/www/" + port + "/broken/reason", value:string("50x"));
      exit(0);
   
   }  

  } 

## if all fail set to 1.0 anyway
set_kb_item(name:string("http/", port), value:string("10"));

exit(0);
