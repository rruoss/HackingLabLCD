# OpenVAS Vulnerability Test
# $Id: remote-MS03-022.nasl 15 2013-10-27 12:49:54Z jan $
# Description: 
# Microsoft Security Bulletin MS03-022
# Vulnerability in ISAPI Extension for Windows Media Services Could Cause Code Execution
# Microsoft Windows Media Services 'nsiislog.dll' Buffer Overflow Vulnerability (MS03-019)
# BUGTRAQ:20030626 Windows Media Services Remote Command Execution #2 
#
# Affected Software: 
# Microsoft Windows 2000 
#
# Not Affected Software Versions:
# Windows NT 4.0 
# Microsoft Windows XP 
# Microsoft Windows Server 2003 
#
# remote-MS03-022.nasl
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
tag_summary = "There is a flaw in the way nsiislog.dll processes incoming client requests. 
A vulnerability exists because an attacker could send specially formed HTTP request (communications) 
to the server that could cause IIS to fail or execute code on the user's system.";

tag_solution = "Microsoft has released a patch to correct these issues
Download locations for this patch

Microsoft Windows 2000: 
http://www.microsoft.com/downloads/details.aspx?FamilyId=F772E131-BBC9-4B34-9E78-F71D9742FED8&displaylang=en 
 
Note: This patch can be installed on systems running Microsoft Windows 2000 Service Pack 2, 
Windows 2000 Service Pack 3 and Microsoft Windows 2000 Service Pack 4. 
This patch has been superseded by the one provided in Microsoft Security Bulletin MS03-019. 
http://www.microsoft.com/technet/security/bulletin/MS03-019.mspx";




if(description)
{
script_id(101016);
script_version("$Revision: 15 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");
script_cve_id("CVE-2003-0349");
name = "Microsoft MS03-022 security check";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;


script_description(desc);
 
summary = "ISAPI Extension for Windows Media Services Remote Code Execution Vulnerability";
 
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


web_servers = get_kb_item("Services/www");

h_ip = get_host_ip();

remote_exe = '';



foreach port (web_servers)
{
	soc = open_sock_tcp(port);
	
	# request the page
	qry = string("GET /" , "/scripts/nsiislog.dll" , ' HTTP/1.0\r\n',
			"Host: " , h_ip , "\r\n",
			"Connection: Keep-Alive\r\n\r\n");
				
	req = http_get(item:qry, port:port);
	send(socket:soc, data:req);
				
	# get back the response
	reply = recv(socket:soc, length:4096);
	
	if(reply)
	{
		if('NetShow ISAPI Log Dll' >< reply)
		{
			url_args = make_list('date', 'time', 
					'c-dns', 'cs-uri-stem', 'c-starttime', 'x-duration', 'c-rate', 
					'c-status', 'c-playerid',  'c-playerversion', 'c-player-language', 
					'cs(User-Agent)', 'cs(Referer)', 'c-hostexe');

			foreach parameter (url_args) remote_exe += parameter + "=openvas&";
			
			remote_exe += 'c-ip=' + crap(65535);
			
			# build the media player client request
			mpclient = string("POST /", "/scripts/nsiislog.dll", " HTTP/1.0\r\n",
			"Host: ", h_ip, "\r\n",
			"User-Agent: ", "NSPlayer/2.0", "\r\n",
			"Content-Type: ", "application/x-www-form-urlencoded" , "\r\n",
			"Content-Length: ",  strlen(remote_exe) , "\r\n\r\n");
			
			req2 = http_post(item:mpclient, port:port);
			send(socket:soc, data:req2);
			#send(socket:soc, data:remote_exe);
			
			response = recv(socket:sock, length:4096);
			if((egrep(pattern:"HTTP/1.[01] 500", string:response)) && ('The remote procedure call failed. ' >< response)) security_hole(port);
		}
	}		
}	
