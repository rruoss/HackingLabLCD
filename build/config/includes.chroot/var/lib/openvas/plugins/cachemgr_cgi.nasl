# OpenVAS Vulnerability Test
# $Id: cachemgr_cgi.nasl 17 2013-10-27 14:01:43Z jan $
# Description: RedHat 6.0 cachemgr.cgi
#
# Authors:
# Alexis de Bernis <alexisb@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 1999 A. de Bernis
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
tag_summary = "RedHat Linux 6.0 installs by default a squid cache manager cgi script with
no restricted access permissions. This script could be used to perform a
port scan from the cgi-host machine.";

tag_solution = "If you are not using the box as a Squid www proxy/cache server then
uninstall the package by executing:
/etc/rc.d/init.d/squid stop ; rpm -e squid

If you want to continue using the Squid proxy server software, make the
following actions to tighten security access to the manager interface:
mkdir /home/httpd/protected-cgi-bin
mv /home/httpd/cgi-bin/cachemgr.cgi /home/httpd/protected-cgi-bin/

And add the following directives to /etc/httpd/conf/access.conf and
srm.conf:

--- start access.conf segment ---
# Protected cgi-bin directory for programs that
# should not have public access
order deny,allow
deny from all
allow from localhost
#allow from .your_domain.com
AllowOverride None
Options ExecCGI
--- end access.conf segment ---

--- start srm.conf segment ---
ScriptAlias /protected-cgi-bin/ /home/httpd/protected-cgi-bin/
--- end srm.conf segment ---";


if(description)
{
 script_id(10034);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2059);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-1999-0710");
 name = "RedHat 6.0 cachemgr.cgi";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 
 script_description(desc);
 
 summary = "Checks whether the cachemgr.cgi is installed and accessible."; 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 1999 A. de Bernis");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl",  "no404.nasl");
 script_require_ports("Services/www", 80);
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

cgi = "cachemgr.cgi";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);
