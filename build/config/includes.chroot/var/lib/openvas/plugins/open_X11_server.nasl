# OpenVAS Vulnerability Test
# $Id: open_X11_server.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Open X Server
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
tag_summary = "An improperly configured X server will accept connections from clients from 
anywhere. This allows an attacker to make a client connect to the X server to 
record the keystrokes of the user, which may contain sensitive information,
such as account passwords.

To solve this problem, use xauth or MIT cookies.";

tag_solution = "Use xhost, MIT cookies, and filter incoming TCP connections to this
port.";

# To be consistent with the "one plugin = one flaw" principle, 
# I split X.nasl in two parts. This script only process results from 
# X.nasl

if(description)
{
  script_id(15897);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-1999-0526");

  name = "Open X Server";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
 script_description(desc);

 summary = "An open X Window System Server is present";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_dependencies("X.nasl");
 script_require_ports("Services/X11");
 
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
 exit(0);
}

port = get_kb_item("Services/X11");
if (! port) exit(0);	# or port = 6000 ?
open = get_kb_item("X11/"+port+"/open");
if (! open) exit(0);

ver = get_kb_item("X11/"+port+"/version");
textresult = get_kb_item("X11/"+port+"/answer");
report = string("This X server accepts clients from anywhere. This\n",
	    	"allows an attacker to connect to it and record any of your keystrokes.\n\n",
		"Here is the server version : ", ver, "\n",
		"Here is the server type : ", textresult, "\n\n",
		"Solution: use xauth or MIT cookies to restrict the access to this server");

security_hole(port:port, data:report);	
