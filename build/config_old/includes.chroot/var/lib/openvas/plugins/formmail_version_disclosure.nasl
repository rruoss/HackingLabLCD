# OpenVAS Vulnerability Test
# $Id: formmail_version_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Formmail Version Information Disclosure
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
tag_summary = "Matt Wright's Formmail CGI is installed on the remote host.
The product exposes its version number, and in addition, 
early versions of the product suffered from security 
vulnerabilities, which include: allowing SPAM, file disclosure, 
environment variable disclosure, and more.";

tag_solution = "Upgrade to the latest version.

Additional information:
http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=Formmail";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(10782);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0357");

 name = "Formmail Version Information Disclosure";
 script_name(name);

 script_description(desc);

 summary = "Formmail Version Information Disclosure";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl", "no404.nasl");
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


dir = make_list(cgi_dirs());


program[0] = "/formmail.pl";
program[1] = "/formmail.pl.cgi";
program[2] = "/FormMail.cgi";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

for (i = 0; dir[i] ; i = i + 1)
{
 for (j = 0; program[j] ; j = j + 1)
 {
   url = string(dir[i], program[j]);
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
   if(buf == NULL)exit(0);
   if ("Version " >< buf && buf =~ '<title>FormMail v[0-9.]+</title>')
     {
       v = ereg_replace(string: buf, replace: "\1",
			pattern: '.*<title>FormMail v([0-9.]+)</title>.*'); 
       if (v == '1.92') # Latest available version?
        {
          report =  "
Matt Wright's Formmail CGI is installed on the remote host.
The product exposes its version number.

Additional information:
http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=Formmail";
       security_hole(port:port, data:report);
       exit(0);
       }
       else
       {
       report = string(desc, "\n", "Version : ", v);
       security_hole(port:port, data:report);
       exit(0);
       }
     }
   else if ("FormMail</a> V" >< buf)
    {
     #report = string(desc, "\n", "Version : ", buf);
     report = desc;
     security_hole(port:port, data:report);
     exit(0);
    }
 }
}
