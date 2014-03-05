# OpenVAS Vulnerability Test
# $Id: kiwi_cattools_dir_traversal.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Kiwi CatTools < 3.2.9 Directory Traversal
#
# Authors:
# Ferdy Riphagen 
#
# Copyright:
# Copyright (C) 2007 Ferdy Riphagen
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
tag_summary = "The remote tftpd server is affected by a directory traversal vulnerability.

Description :

Kiwi CatTools is installed on the remote host. The version installed is vulnerable
to a directory traversal attack by using '[char]//..' sequences in the path. A attacker may be able to read and
write files outside the tftp root.";

tag_solution = "Upgrade to Kiwi CatTools version 3.2.9 or later.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if (description) {
 script_id(200001);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_cve_id("CVE-2007-0888");
 script_bugtraq_id(22490);

 name = "Kiwi CatTools < 3.2.9 Directory Traversal";
 script_name(name);
 script_description(desc);
 summary = "Try to grab a file outside the tftp root";
 script_summary(summary);

 script_category(ACT_ATTACK);
 script_family("Remote file access");
 script_copyright("This script is Copyright (C) 2007 Ferdy Riphagen");

 script_dependencies("tftpd_detect.nasl");
 script_require_keys("Services/udp/tftp");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.kiwisyslog.com/kb/idx/5/178/article/");
 script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&amp;m=117097429127488&amp;w=2");
 exit(0);
}

include("tftp.inc");

port = get_kb_item("Services/udp/tftp");
if (!port) port = 69;

get = tftp_get(port:port, path:"z//..//..//..//..//..//boot.ini");
if (isnull(get)) exit(0);
if (egrep(pattern:"default=multi.*disk.*partition", string:get)) {
    report = string(
	desc, "\n\n", "Plugin output :\n\n",
	"The boot.ini file contains:\n", get); 
    security_hole(port, data:report);
    exit(0);
}
