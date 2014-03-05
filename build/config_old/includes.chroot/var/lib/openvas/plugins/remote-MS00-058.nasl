# OpenVAS Vulnerability Test
# $Id: remote-MS00-058.nasl 15 2013-10-27 12:49:54Z jan $
# Description: 
# Microsoft Security Bulletin MS04-017
# Vulnerability in Crystal Reports Web Viewer Could Allow Information Disclosure and Denial of Service 
#
# remote-MS00-058.nasl
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
tag_summary = "This vulnerability could cause a IIS 5.0 web server to send the source code of certain types of web files to a visiting user.";

tag_solution = "Microsoft has released a patch to fix this issue, download it from the following website: 
http://www.microsoft.com/technet/security/bulletin/ms00-058.mspx";

 

 
 if(description)
{
script_id(101003);
script_version("$Revision: 15 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2009-03-15 20:49:44 +0100 (Sun, 15 Mar 2009)");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_tag(name:"risk_factor", value:"Medium");
script_bugtraq_id(10260);
script_cve_id("CVE-2000-0778");
name = "Microsoft MS00-058 security check";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
script_description(desc);

summary = "Microsoft Specialized Header Vulnerability";

script_summary(summary);

script_category(ACT_ATTACK);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Windows : Microsoft Bulletins";
script_family(family);
script_dependencies("find_service.nasl");
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


iis_servers = get_kb_list("Services/www");

# Asp files the plugin will test
pages  = make_array( 0, 'default.asp', 1, 'iisstart.asp', 2, 'localstart.asp');
matches = make_array(0, "application/octet-stream", 1, "<% @Language = 'VBScript' %>");

# get the target ip address
h_ip = get_host_ip();


# connect to the remote host
foreach port (iis_servers)
{
	foreach asp_file (pages)
	{
		soc = open_sock_tcp(port);
		if(!soc)continue;
		
		qry = string('GET /' + asp_file + ' HTTP/1.0\r\n',
 			  'Host: ' + h_ip + ':' + port + '\r\n',
			  'Translate: f\r\n\r\n');
		
		req = http_get(item:qry, port:port);
		send(socket:soc, data: req);

		# Get back the response
		reply = recv(socket:soc, length:1204);

		close(soc);

		if(reply)
		{
			r = tolower(reply);
			content_type = egrep(patern:"Content-Type", string:r, icase:TRUE);
			if(("Microsoft-IIS" >< r ) && (egrep(pattern:"HTTP/1.[01] 200", string:r, icase:TRUE)) && (matches[0] == content_type))
			{
				if(egrep(pattern:matches[1], string:r, icase:TRUE))
					# Report 'Microsoft IIS 'Specialiazed Header' (MS00-058)' Vulnerability
					security_warning(port);
			}
		}
	}
}
