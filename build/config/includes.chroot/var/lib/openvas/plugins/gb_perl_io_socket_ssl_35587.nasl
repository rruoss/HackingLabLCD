###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_io_socket_ssl_35587.nasl 14 2013-10-27 12:33:37Z jan $
#
# Perl IO::Socket::SSL 'verify_hostname_of_cert()' Security Bypass Vulnerability
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
tag_summary = "The IO::Socket::SSL module for Perl is prone to a security-
bypass vulnerability because the application fails to properly
validate certificate hostnames.

Successfully exploiting this issue allows attackers to bypass certain
security restrictions, which may aid in further attacks.

Versions prior to IO::Socket::SSL 1.26 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100674);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)");
 script_bugtraq_id(35587);
 script_cve_id("CVE-2009-3024");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Perl IO::Socket::SSL 'verify_hostname_of_cert()' Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/35587");
 script_xref(name : "URL" , value : "http://search.cpan.org/dist/IO-Socket-SSL/");
 script_xref(name : "URL" , value : "http://cpansearch.perl.org/src/SULLR/IO-Socket-SSL-1.26/Changes");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if IO::Socket::SSL version is < 1.26");
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

cmd  = "perl -MIO::Socket::SSL -e 'print";
cmd += '"$IO::Socket::SSL::VERSION"';
cmd += "'";

version = ssh_cmd(socket:sock, cmd:cmd, timeout:60);

if(!version || "not found" >< version || "@INC" >< version || version !~ "^[0-9.]+$")exit(0);

if(version_is_less(version: version, test_version: "1.26")) {
  security_warning(0);
}

ssh_close_connection();
exit(0);
