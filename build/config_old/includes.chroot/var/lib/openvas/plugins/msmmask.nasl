# OpenVAS Vulnerability Test
# $Id: msmmask.nasl 17 2013-10-27 14:01:43Z jan $
# Description: msmmask.exe
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "The msmmask.exe CGI is installed.
Some versions allow an attacker to read the source of any
file in your webserver's directories by using the 'mask'
parameter.";

tag_solution = "Upgrade your MondoSearch to version 4.4.5156 or later.";

# Affected: MondoSearch 4.4.5147 and below.
#           MondoSearch 4.4.5156 and above are NOT vulnerable.
#
# References:
#
# Message-ID: <20021010180935.14148.qmail@mail.securityfocus.com>
# From:"thefastkid" <thefastkid@ziplip.com>
# To:bugtraq@securityfocus.com
# Subject: MondoSearch show the source of all files

if(description)
{
 script_id(11163);
 script_version("$Revision: 17 $");
 script_cve_id("CVE-2002-1528");
 script_bugtraq_id(5941);
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
  
 name = "msmmask.exe";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;






 script_description(desc);
 
 summary = "Checks for the presence of /cgi-bin/msmMask.exe";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");

 family = "Web application abuses";
 script_family(family);
 	

 script_dependencies("find_service.nasl", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs())
{
p = string(dir, "/MsmMask.exe");
q = string(p, "?mask=/openvas", rand(), ".asp");
r = http_get(port: port, item: q);
c = http_keepalive_send_recv(port:port, data:r);
if (egrep(pattern: "Failed to read the maskfile .*openvas.*\.asp",
	string: c, icase: 1))
  {
    security_warning(port);
    exit(0);
  }

# Version at or below 4.4.5147
if (egrep(pattern: "MondoSearch for Web Sites (([0-3]\.)|(4\.[0-3]\.)|(4\.4\.[0-4])|(4\.4\.50)|(4\.4\.51[0-3])|(4\.4\.514[0-7]))", string: c))
  {
    security_warning(port);
    exit(0);
  }
}


