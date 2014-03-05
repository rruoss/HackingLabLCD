# OpenVAS Vulnerability Test
# $Id: cvstrac_jail_escape.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CVSTrac chdir() chroot jail escape
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The remote host seems to be running cvstrac, 
a web-based bug and patch-set tracking system for CVS.

This version contains a flaw related to the chdir() function 
that may allow an attacker to escape the chroot jail.  An
attacker, exploiting this flaw, would be able to access files
outside of the web root.

***** OpenVAS has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of CVSTrac
***** installed there.";

tag_solution = "Update to version 1.1.4 or disable this CGI suite";

if(description)
{
 script_id(14288);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_xref(name:"OSVDB", value:"8643");
 name = "CVSTrac chdir() chroot jail escape";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks for CVSTrac version";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("cvstrac_detect.nasl");
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

port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1]; 
if(ereg(pattern:"^(0\.|1\.(0|1\.[0-3]([^0-9]|$)))", string:version))
	security_hole(port);

