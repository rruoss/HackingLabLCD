# OpenVAS Vulnerability Test
# $Id: PagesPro_dir_trav.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Pages Pro CD directory traversal
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
tag_summary = "A security vulnerability in the 'Pages Pro' allows anybody
to read or modify files that would otherwise be inaccessible using a 
directory traversal attack. 
A cracker may use this to read or write sensitive files or even 
make a phone call.

http://www.certa.ssi.gouv.fr/site/CERTA-2002-ALE-007/index.html.2.html";

tag_solution = "Upgrade it (version 2003) or uninstall this product";

# Reference
# http://www.certa.ssi.gouv.fr/site/CERTA-2002-ALE-007/index.html.2.html
#
# Credits:
# Philippe de Brito (Le Mamousse) discovered the flaw and sent his exploit.

if(description)
{
 script_id(11221);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Pages Pro CD directory traversal";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Pages Pro CD directory traversal";
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 8100);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# 

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8100);
foreach port (ports)
{
 file[0] = "windows/win.ini";
 file[1] = "winnt/win.ini";

 for (i = 0; file[i]; i = i + 1)
 { 
  u = string("/note.txt?F_notini=&T_note=&nomentreprise=blah&filenote=../../",
             file[i]);
  if(check_win_dir_trav_ka(port: port, url:u))
  {
    security_hole(port);
    break;
  }
 }
}

