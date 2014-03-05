# OpenVAS Vulnerability Test
# $Id: cfengine_format_string_vuln.nasl 17 2013-10-27 14:01:43Z jan $
# Description: cfengine format string vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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
tag_summary = "Cfengine is running on this remote host.

Cfengine contains a component, cfd, which serves as a remote-configuration
client to cfengine.  This version of cfd contains several flaws in the
way that it calls syslog().  As a result, trusted hosts and valid users
(if access controls are not in place) can cause the vulnerable host to
log malicious data which, when logged, can either crash the server or
execute arbitrary code on the stack.  In the latter case, the code would
be executed as the 'root' user.";

tag_solution = "Upgrade to 1.6.0a11 or newer";

# Ref: Pekka Savola <pekkas@netcore.fi>

if(description)
{
 script_id(14316);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1757);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-2000-0947");
 script_xref(name:"OSVDB", value:"1590");

 name = "cfengine format string vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "check for cfengine flaw based on its version";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Gain a shell remotely";
 
 script_family(family);
 script_require_ports(5308);

 script_dependencies("cfengine_detect.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

port = 5308;
if ( ! get_kb_item("cfengine/running") ) exit(0);

version = get_kb_item("cfengine/version");

if (version)
{
 	if (egrep(pattern:"1\.([0-5]\..*|6\.0a([0-9]|10)[^0-9])", string:version))
  		security_hole(port);
}
