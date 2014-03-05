###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ejabberd_50737.nasl 13 2013-10-27 12:16:33Z jan $
#
# ejabberd 'mod_pubsub' Module Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "ejabberd is prone to a vulnerability that may allow attackers to cause
an affected application to enter an infinite loop, resulting in a denial-of-
service condition.

ejabberd versions prior to 2.1.9 are affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103369);
 script_bugtraq_id(50737);
 script_cve_id("CVE-2011-4320");
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_name("ejabberd 'mod_pubsub' Module Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50737");
 script_xref(name : "URL" , value : "http://www.ejabberd.im/");
 script_xref(name : "URL" , value : "http://www.process-one.net/en/ejabberd/release_notes/release_note_ejabberd_2.1.9/");
 script_xref(name : "URL" , value : "https://support.process-one.net/browse/EJAB-1498");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-12-20 11:14:21 +0100 (Tue, 20 Dec 2011)");
 script_description(desc);
 script_summary("Determine if installed ejabberd version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("ejabberd_detect.nasl");
 script_require_ports("Services/xmpp", 5222);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

xmpp_port = get_kb_item("Services/xmpp");
if(!xmpp_port)xmpp_port=5222;
if(!get_port_state(xmpp_port))exit(0);

if(!version = get_kb_item(string("xmpp/", xmpp_port, "/ejabberd")))exit(0);
if(!isnull(version)) {

    if(version_is_less(version: version, test_version: "2.1.9")) {
            security_warning(port:xmpp_port);
            exit(0);
    }

}

exit(0);
