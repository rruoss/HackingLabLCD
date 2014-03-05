# OpenVAS Vulnerability Test
# $Id: dada_mail_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: XSS vulnerability in Dada Mail
#
# Authors:
# Josh Zlatin-Amishav <josh at ramat dot cc>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "The remote host is running Dada Mail, a free, e-mail list management
system written in Perl. 

According to its banner, the remote version of this software does not
properly validate user written content before submitting that data to
the archiving system.  A malicious user could embed arbitrary
javascript in archived messages to later be executed in a user's
browser within the context of the affected web site.";

tag_solution = "Upgrade to version 2.10 alpha 1 or higher.";

if(description)
{
 script_id(19679);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2005-2595");
 script_bugtraq_id(14573);
 script_xref(name:"OSVDB", value:"18772");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "XSS vulnerability in Dada Mail";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Checks Dada Mail version";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?release_id=349531");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (thorough_tests) dirs = make_list("/cgi-bin/dada", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 req = http_get(
   item:string(
     dir, "/mail.cgi"
   ), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 # versions 2.9.x are vulnerable
 if(egrep(pattern:"Powered by.*Dada Mail 2\.9", string:res))
 {
        security_warning(port);
        exit(0);
 }
}
