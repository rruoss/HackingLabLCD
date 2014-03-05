# OpenVAS Vulnerability Test
# $Id: open_nntp_server.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Open News server
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
tag_solution = "Enforce authentication or filter connections from outside";

tag_summary = "The remote server seems open to outsiders.
Some people love open public NNTP servers to
be able to read or post articles anonymously.
Keep in mind that robots are harvesting such 
open servers on Internet, so you cannot hope that
you will stay hidden for long.

Unwanted connections could waste your bandwith
or put you into legal trouble if outsiders use your server
to read or post 'politically incorrects' articles.

** As it is very common to have IP based authentication,
** this might be a false positive if the OpenVAS scanner is
** among the allowed source addresses.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(17204);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Open News server";
 script_name(name);
 
 script_description(desc);
 
 summary = "Public NNTP server is open to outside";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "General";
 script_family(family);

 script_dependencies("nntp_info.nasl");
 script_require_ports("Services/nntp", 119);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#

include('global_settings.inc');
include('network_func.inc');

# Unusable server
if (! get_kb_item('nntp/'+port+'/ready') ||
    ! get_kb_item('nntp/'+port+'/noauth') )
 exit(0);

# Only warn on private addresses. The server might be accessible
# through NAT, so we warn if we prefere FP
if (report_paranoia < 2 && is_private_addr()) exit(0);

post = get_kb_item('nntp/'+port+'/posting');
# If we want to avoid FP, check that the message was posted
if (post && report_paranoia < 1 && get_kb_item('nntp/'+port+'/posted') <= 0)
  post = 0;

if (! post) 
  desc = str_replace(string: desc, find: 'read and post', replace: 'read');
security_hole(port: port, data: desc);
