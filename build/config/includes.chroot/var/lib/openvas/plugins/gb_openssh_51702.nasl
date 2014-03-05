###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_51702.nasl 12 2013-10-27 11:15:33Z jan $
#
# openssh-server Forced Command Handling Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "The auth_parse_options function in auth-options.c in sshd in OpenSSH before 5.7
provides debug messages containing authorized_keys command options, which allows
remote authenticated users to obtain potentially sensitive information by
reading these messages, as demonstrated by the shared user account required by
Gitolite. NOTE: this can cross privilege boundaries because a user account may
intentionally have no shell or filesystem access, and therefore may have no
supported way to read an authorized_keys file in its own home directory.

OpenSSH before 5.7 is affected;";

tag_solution = "Updates are available. Please see the references for more information.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if (description)
{
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51702");
 script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=657445");
 script_xref(name : "URL" , value : "http://packages.debian.org/squeeze/openssh-server");
 script_xref(name : "URL" , value : "https://downloads.avaya.com/css/P8/documents/100161262");
 script_id(103503);
 script_bugtraq_id(51702);
 script_cve_id("CVE-2012-0814");
 script_tag(name:"cvss_base", value:"3.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
 script_version ("$Revision: 12 $");

 script_name("openssh-server Forced Command Handling Information Disclosure Vulnerability");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-06-28 11:05:31 +0200 (Thu, 28 Jun 2012)");
 script_description(desc);
 script_summary("Determine if installed OpenSSH version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("backport.inc");
include("version_func.inc");

port = get_kb_item("Services/ssh");
if(!port){
    port = 22;
}

if(!get_port_state(port))exit(0);

banner = get_kb_item("SSH/banner/" + port );
if(!banner || "openssh" >!< tolower(banner)) {
    exit(0); 
}

banner = tolower(get_backport_banner(banner:banner));
ver = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string:banner);

if(isnull(ver[1])){
   exit(0);
}

if(version_is_less(version:ver[1], test_version:"5.7")) {
  desc = 'According to its banner, the version of OpenSSH installed on the remote\nhost is older than 5.7:\n ' + banner + '\n\n' + desc;

  security_warning(port:port, data:desc);
  exit(0);
}  

exit(0);
