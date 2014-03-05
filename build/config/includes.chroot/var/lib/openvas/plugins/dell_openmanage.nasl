# OpenVAS Vulnerability Test
# $Id: dell_openmanage.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Dell OpenManage Web Server <= 3.7.1
#
# Authors:
# Tomi Hanninen <Tomi.Hanninen@thermo.com>
#
# Copyright:
# Copyright (C) 2004 Tomi Hanninen
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
tag_summary = "The remote host is running the Dell OpenManage Web Server.

Dell OpenManage Web Servers 3.2.0-3.7.1 are vulnerable to a heap based 
buffer overflow attack. A proof of concept denial of service attack has been 
released.

*** Note : The Dell patch does not increase the version number of this service
*** so this may be a false positive

Patch is available at http://support.dell.com/filelib/download.asp?FileID=96563&c=us&l=en&s=DHS&Category=36&OS=WNT5&OSL=EN&SvcTag=&SysID=PWE_FOS_XEO_6650&DeviceID=2954&Type=&ReleaseID=R74029";

tag_solution = "Install the security patch available from Dell";

# ref: http://sh0dan.org/files/domadv.txt

if(description)
{
	script_id(12295);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
	script_cve_id("CVE-2004-0331");
	script_bugtraq_id(9750);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
	name = "Dell OpenManage Web Server <= 3.7.1";
	script_name(name);

	desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

	script_description(desc);

	summary = "Dell OpenManage Web Server 3.2.0-3.7.1 are vulnerable to a heap based buffer overflow";

	script_summary(summary);
	script_family("Denial of Service");

	script_copyright("This is script is Copyright (C) 2004 Tomi Hanninen");
	script_require_ports(1311);
	script_category(ACT_GATHER_INFO);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://sh0dan.org/files/domadv.txt");
exit(0);
}

#
# Actual script
#

include("http_func.inc");
include("http_keepalive.inc");

port = 1311;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);


url = "/servlet/UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin";
request = http_get(port:port, item:url);

if(soc)
{	
	send(socket:soc, data:request);
	buffer = http_recv(socket:soc);
	close(soc);
	
	# This will search for the version line
	# it _should_ match versions 3.2.0-3.6.9 and 3.7.0
	if ( egrep(pattern:"<br>Version ([0-2]\.|3\.[2-6]\.)|(3\.7\.[0-1])<br>", string:buffer) ) 
	 {
	   security_warning(port); 
	 } 
}
