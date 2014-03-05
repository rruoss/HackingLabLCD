# OpenVAS Vulnerability Test
# $Id: cvs_file_existence_info_weak.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CVS file existence information disclosure weakness
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
tag_summary = "The remote CVS server, according to its version number,
can be exploited by malicious users to gain knowledge of 
certain system information.

This behaviour can be exploited to determine the existence 
and permissions of arbitrary files and directories on a 
vulnerable system.";

tag_solution = "Upgrade to CVS 1.11.17 and 1.12.9, or newer";

# Ref: Sebastian Krahmer

if(description)
{
 script_id(14313);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10955);
 script_cve_id("CVE-2004-0778");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 
 name = "CVS file existence information disclosure weakness";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Logs into the remote CVS server and asks the version";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "General";
 script_family(family);
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service.nasl", "cvspserver_version.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

port = get_kb_item("Services/cvspserver");
if(!port) port = 2401;
if(!get_port_state(port)) exit(0);

version = get_kb_item(string("cvs/", port, "/version"));
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-6])|12\.[0-8][^0-9]).*", string:version))
     		security_warning(port);
