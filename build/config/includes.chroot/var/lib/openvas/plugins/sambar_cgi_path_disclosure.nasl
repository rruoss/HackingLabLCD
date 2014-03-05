# OpenVAS Vulnerability Test
# $Id: sambar_cgi_path_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sambar CGIs path disclosure
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "environ.pl or testcgi.exe is installed. Those CGIs
reveal the installation directory and some other information 
that could help a cracker.";

tag_solution = "remove them";

# References:
# From: <gregory.lebras@security-corporation.com>
# To: vulnwatch@vulnwatch.org
# Date: Thu, 27 Mar 2003 15:25:40 +0100
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server
#
# Vulnerables:
# Sambar WebServer v5.3 and below 

if(description)
{
 script_id(11775);
 script_version("$Revision: 17 $");
 script_bugtraq_id(7207, 7208);
 script_cve_id("CVE-2003-1284");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Sambar CGIs path disclosure");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Some CGIs reveal the web server installation directory";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/sambar");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if (http_is_dead(port: port)) exit(0);

files = make_list("cgitest.exe", "environ.pl");
dirs = cgi_dirs();

foreach dir (dirs)
{
  foreach fil (files)
  {
    soc = http_open_socket(port);
    if (! soc) exit(0);
    req = http_get(port: port, item: strcat(dir, "/", fil));
    r = http_keepalive_send_recv(port:port, data: req);
    p = strcat("SCRIPT_FILENAME:*", fil);
    if (r && (match(string: r, pattern: p) || r =~ 'DOCUMENT_ROOT:[\t]*[A-Z]\\\\'))
    {
      security_warning(port);
      exit(0);
    }
  }
}

