###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openaudit_40315.nasl 14 2013-10-27 12:33:37Z jan $
#
# Open-Audit Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Open-Audit is prone to multiple vulnerabilities, including a local file-
include vulnerability and multiple SQL-injection, cross-site
scripting, and authentication-bypass vulnerabilities.

An attacker can exploit these vulnerabilities to steal cookie-based
authentication credentials, compromise the application, access or
modify data, exploit latent vulnerabilities in the underlying
database, bypass security restrictions, obtain potentially sensitive
information, perform unauthorized actions, or execute arbitrary local
scripts in the context of the webserver process; other attacks are
also possible.

Open-Audit 20081013 and 20091223-RC are vulnerable; other versions may
also be affected.";


if (description)
{
 script_id(100654);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-25 18:01:00 +0200 (Tue, 25 May 2010)");
 script_bugtraq_id(40315);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Open-Audit Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40315");
 script_xref(name : "URL" , value : "http://www.open-audit.org/index.php");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Open-Audit is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/open-audit","/openaudit","/open_audit",cgi_dirs());
foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"<title>Open-AudIT</title>")) {
    
    url = string(dir,"/list.php?view=%3Cscript%3Ealert(%27OpenVAS-XSS-Test%27)%3B%3C%2Fscript%3E");

    if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('OpenVAS-XSS-Test'\);</script>")) {

      security_hole(port:port);
      exit(0);

    }

  }
}

exit(0);
