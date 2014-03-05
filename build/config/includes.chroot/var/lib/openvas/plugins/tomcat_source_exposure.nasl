# OpenVAS Vulnerability Test
# $Id: tomcat_source_exposure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Tomcat 4.x JSP Source Exposure
#
# Authors:
# Felix Huber <huberfelix@webtopia.de>
# Changes by Tenable : removed un-necessary requests
#
# Copyright:
# Copyright (C) 2002 Felix Huber
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
tag_summary = "Tomcat 4.0.4 and 4.1.10 (probably all other 
earlier versions also) are vulnerable to source 
code exposure by using the default servlet
org.apache.catalina.servlets.DefaultServlet.";

tag_solution = "Upgrade to the last releases 4.0.5 and 4.1.12.
See http://jakarta.apache.org/builds/jakarta-tomcat-4.0/release/ 
for the last releases.";

# v. 1.00 (last update 24.09.02)

if(description)
{
 script_id(11176);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5786);
 script_cve_id("CVE-2002-1148");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Tomcat 4.x JSP Source Exposure";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Tomcat 4.x JSP Source Exposure";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 2002 Felix Huber");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

function check(sfx)
{
 
   url = string("/servlet/org.apache.catalina.servlets.DefaultServlet", sfx);
   req = http_get(item:url, port:port);
   r = http_keepalive_send_recv(port:port, data:req);
   if( r == NULL ) exit(0);

   if("<%@" >< r){
       security_warning(port);
       exit(0);
      }
      
    if(" 200 OK" >< r)
    {
     if("Server: Apache Tomcat/4." >< r)
     {
                security_warning(port); 
                exit(0); 
      } 
    }
}


 
port = get_http_port(default:80);


if(!get_port_state(port))exit(0);





files = get_kb_list(string("www/",port, "/content/extensions/jsp"));
if(!isnull(files))
 {
  files = make_list(files);
  file = files[0];
 }
else file = "/index.jsp";

check(sfx:file);
 
