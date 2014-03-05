###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_cgi_44892.nasl 14 2013-10-27 12:33:37Z jan $
#
# Perl MIME Boundary 'multipart_init' Unspecified Security Vulnerability
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
tag_summary = "Perl is prone to an unspecified security vulnerability because the
MIME part of the 'multipart_init' is not random.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100907);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-17 12:37:13 +0100 (Wed, 17 Nov 2010)");
 script_bugtraq_id(44892);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Perl MIME Boundary 'multipart_init' Unspecified Security Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44892");
 script_xref(name : "URL" , value : "http://perl5.git.perl.org/perl.git/commit/84601d63a7e34958da47dad1e61e27cb3bd467d1");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Perl CGI version is vulnerable");
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

cmd  = "perl -MCGI -e 'print";
cmd += '"$CGI::VERSION"';
cmd += "'";

version = ssh_cmd(socket:sock, cmd:cmd, timeout:60);

if(!version || "not found" >< version || "@INC" >< version || version !~ "^[0-9.]+$")exit(0);

if(version_is_less(version: version, test_version: "3.50")) {
    security_warning(0);
}

ssh_close_connection();
exit(0);
