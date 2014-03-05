###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_49473.nasl 13 2013-10-27 12:16:33Z jan $
#
# OpenSSH Ciphersuite Specification Information Disclosure Weakness
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "OpenSSH is prone to a security weakness that may allow attackers to
downgrade the ciphersuite.

Successfully exploiting this issue in conjunction with other latent
vulnerabilities may allow attackers to gain access to sensitive
information that may aid in further attacks.

Releases prior to OpenSSH 2.9p2 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103247);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-09-09 13:52:42 +0200 (Fri, 09 Sep 2011)");
 script_bugtraq_id(49473);
 script_cve_id("CVE-2001-0572");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("OpenSSH Ciphersuite Specification Information Disclosure Weakness");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49473");
 script_xref(name : "URL" , value : "http://www.openssh.com");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/596827");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed OpenSSH version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

if(report_paranoia < 2) exit(0); # this nvt is pront to FP

port = get_kb_item("Services/ssh");
if(!port) port = 22;

if(!get_port_state(port))exit(0);

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);

version = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string: banner,icase:TRUE);
if(isnull(version[1]))exit(0);

if(version_is_less(version: version[1], test_version: "2.9p2")) {
 security_hole(port);
 exit(0);
}

exit(0);