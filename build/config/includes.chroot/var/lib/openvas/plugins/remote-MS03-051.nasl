# OpenVAS Vulnerability Test
# $Id: remote-MS03-051.nasl 15 2013-10-27 12:49:54Z jan $
# Description: 
# Microsoft Security Bulletin MS03-051
# Buffer Overrun in Microsoft FrontPage Server Extensions Could Allow Code Execution
# SmartHTML interpreter denial of service vulnerability: CAN-2003-0824
#
# Affected Software: 
# Microsoft Windows 2000 Service Pack 2, Service Pack 3
# Microsoft Windows XP, Microsoft Windows XP Service Pack 1
# Microsoft Windows XP 64-Bit Edition, Microsoft Windows XP 64-Bit Edition Service Pack 1
# Microsoft Office XP, Microsoft Office XP Service Pack 1, Service Pack 2
# Microsoft Office 2000 Server Extensions
#
# Non Affected Software: 
# Microsoft Windows Millennium Edition 
# Microsoft Windows NT Workstation 4.0, Service Pack 6a 
# Microsoft Windows NT Server 4.0, Service Pack 6a 
# Microsoft Windows NT Server 4.0, Terminal Server Edition, Service Pack 6 
# Microsoft Windows 2000 Service Pack 4 
# Microsoft Windows XP 64-Bit Edition Version 2003 
# Microsoft Windows Server 2003 (Windows SharePoint Services) 
# Microsoft Windows Server 2003 64-Bit Edition (Windows SharePoint Services) 
# Microsoft Office System 2003 
#
# Tested Microsoft Windows and Office Components:
# Affected Components: 
# Microsoft FrontPage Server Extensions 2000 (For Windows NT4) and Microsoft Office 2000 Server Extensions (Shipped with Office 2000)
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=C84C3D10-A821-4819-BF58-D3BC70A77BFA&displaylang=en
# Microsoft FrontPage Server Extensions 2000 (Shipped with Windows 2000) 
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=057D5F0E-0E2B-47D2-9F0F-3B15DD8622A2&displaylang=en
# Microsoft FrontPage Server Extensions 2000 (Shipped with Windows XP) 
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=9B302532-BFAB-489B-82DC-ED1E49A16E1C&displaylang=en
# Microsoft FrontPage Server Extensions 2000 64-bit (Shipped with Windows XP 64-bit) 
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=153A476F-F530-4035-B858-D56FC8A7010F&displaylang=en
# Microsoft FrontPage Server Extensions 2002 
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=3E8A21D9-708E-4E69-8299-86C49321EE25&displaylang=en
# Microsoft SharePoint Team Services 2002 (Shipped with Office XP) 
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=5923FC2F-D786-4E32-8F15-36A1C9E0A340&displaylang=en
#
# remote-MS03-051.nasl
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
tag_summary = "The MS03-051 bulletin addresses two new security vulnerabilities in Microsoft FrontPage Server Extensions, 
the most serious of which could enable an attacker to run arbitrary code on a user's system.
The first vulnerability exists because of a buffer overrun in the remote debug functionality of FrontPage Server Extensions. 
This functionality enables users to remotely connect to a server running FrontPage Server Extensions and remotely debug content using, for example, Visual Interdev. 
An attacker who successfully exploited this vulnerability could be able to run code with IWAM_machinename account privileges on an affected system, 
or could cause FrontPage Server Extensions to fail.
The second vulnerability is a Denial of Service vulnerability that exists in the SmartHTML interpreter. 
This functionality is made up of a variety of dynamic link library files, and exists to support certain types of dynamic web content. 
An attacker who successfully exploited this vulnerability could cause a server running Front Page Server Extensions to temporarily stop responding to requests.";

tag_solution = "Microsoft has released a patch to correct these issues
Download locations for this patch

http://www.microsoft.com/technet/security/bulletin/MS03-051.mspx
Note: This update replaces the security updates contained in the following bulletins: MS01-035 and MS02-053.";




if(description)
{
script_id(101012);
script_version("$Revision: 15 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2009-03-16 00:04:04 +0100 (Mon, 16 Mar 2009)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");
script_cve_id("CVE-2003-0822", "CVE-2003-0824");
name = "Microsoft MS03-051 security check";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;


script_description(desc);
 
summary = "Buffer Overrun in Microsoft FrontPage Server Extensions Could Allow Code Execution";
 
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


iis_servers = get_kb_item("Services/www");

h_ip = get_host_ip();



foreach port (iis_servers)
{
	soc = open_sock_tcp(port);
	
	# request the page
	qry = string('POST ' + '/_vti_bin/_vti_aut/fp30reg.dll' + ' HTTP/1.0\r\n',
			'Connection: Keep-Alive\r\n',
			'Host: ' + h_ip + '\r\n',
			'Transfer-Encoding:', ' chunked\r\n',
			'1\r\n\r\nX\r\n0\r\n\r\n');
			
	qry2 = string('POST ' + '/_vti_bin/_vti_aut/fp30reg.dll' + ' HTTP/1.0\r\n',
			'Connection: Keep-Alive\r\n',
			'Host: ' + h_ip + '\r\n',
			'Transfer-Encoding:', ' chunked\r\n',
			'0\r\n\r\nX\r\n0\r\n\r\n');
			
				
	req = http_get(item:qry, port:port);
	send(socket:soc, data:req);
				
	# get back the response
	reply = recv(socket:soc, length:4096);
	
	if(egrep(patern:"Microsoft-IIS/[45]\.[01]", string:reply, icase:TRUE))
	{
		send(socket:soc, data:qry2);
		response = recv(socket:sock, length:4096);
		
		if(egrep(pattern:"HTTP/1.[01] 200", string:response, icase:TRUE)) 
			security_hole(port);
	}

}	
