# OpenVAS Vulnerability Test
# $Id: cfengine_authdiag.nasl 17 2013-10-27 14:01:43Z jan $
# Description: cfengine AuthenticationDialogue vulnerability
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

cfengine cfservd is reported prone to a remote heap-based buffer 
overrun vulnerability. 

The vulnerability presents itself in the cfengine cfservd 
AuthenticationDialogue() function. The issue exists due to a 
lack of sufficient boundary checks performed on challenge data 
that is received from a client. 

In addition, cfengine cfservd is reported prone to a remote denial 
of service vulnerability. The vulnerability presents itself in the cfengine 
cfservd AuthenticationDialogue() function which is responsible for processing 
SAUTH commands and also performing RSA based authentication.  The vulnerability 
presents itself because return values for several statements within the 
AuthenticationDialogue() function are not checked.";

tag_solution = "Upgrade to 2.1.8 or newer.";

# Ref: Juan Pablo Martinez Kuhn


if(description)
{
 script_id(14314);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1701", "CVE-2004-1702");
 script_bugtraq_id(10899, 10900);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 name = "cfengine AuthenticationDialogue vulnerability";
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
 
 family = "Denial of Service";
 
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
 if (egrep(pattern:"2\.(0\.|1\.[0-7]([^0-9]|$))", string:version))
  security_hole(port);
}
