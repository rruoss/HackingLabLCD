###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_archive_tar_26355.nasl 14 2013-10-27 12:33:37Z jan $
#
# Perl Archive::Tar Module Remote Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Perl Archive::Tar module is prone to a directory-traversal
vulnerability because it fails to validate user-supplied data.

A successful attack can allow the attacker to overwrite files on a
computer in the context of the user running the affected application.
Successful exploits may aid in further attacks.

Note that all applications using Perl Archive::Tar module may
be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100698);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
 script_bugtraq_id(26355);
 script_cve_id("CVE-2007-4829");

 script_name("Perl Archive::Tar Module Remote Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/26355");
 script_xref(name : "URL" , value : "http://search.cpan.org/~kane/Archive-Tar-1.36/lib/Archive/Tar.pm");
 script_xref(name : "URL" , value : "https://issues.rpath.com/browse/RPL-1716?page=com.atlassian.jira.plugin.system.issuetabpanels:all-tabpanel");
 script_xref(name : "URL" , value : "http://rt.cpan.org/Public/Bug/Display.html?id=30380");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_description(desc);
 script_summary("Determine if installed Archive::Tar module version is < 1.36");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","ssh_authorization.nasl");
 script_mandatory_keys("login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
    exit(0);
}

cmd  = "perl -MArchive::Tar -e 'print";
cmd += '"$Archive::Tar::VERSION"';
cmd += "'";

version = ssh_cmd(socket:sock, cmd:cmd, timeout:60);

if(!version || "not found" >< version || "@INC" >< version || version !~ "^[0-9.]+$")exit(0);

if(version_is_less(version: version, test_version: "1.36")) {
  security_hole(0);
}

ssh_close_connection();
exit(0);

