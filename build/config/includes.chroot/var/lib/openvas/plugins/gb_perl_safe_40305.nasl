###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_safe_40305.nasl 14 2013-10-27 12:33:37Z jan $
#
# Perl Safe Module 'reval()' and 'rdo()' CVE-2010-1447 Restriction-Bypass Vulnerabilities
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
tag_summary = "The Perl Safe module is prone to multiple restriction-bypass
vulnerabilities. Successful exploits could allow an attacker
to execute arbitrary Perl code outside of the restricted root.

Versions prior to Safe 2.27 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100673);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)");
 script_bugtraq_id(40305);
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_cve_id("CVE-2010-1447");

 script_name("Perl Safe Module 'reval()' and 'rdo()' Restriction-Bypass Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40305");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-1447");
 script_xref(name : "URL" , value : "http://permalink.gmane.org/gmane.comp.security.oss.general/2932");
 script_xref(name : "URL" , value : "http://cpansearch.perl.org/src/RGARCIA/Safe-2.27/Changes");
 script_xref(name : "URL" , value : "http://search.cpan.org/~rgarcia/Safe-2.27/Safe.pm");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine Safe version is < 2.27");
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

cmd  = "perl -MSafe -e 'print";
cmd += '"$Safe::VERSION"';
cmd += "'";

version = ssh_cmd(socket:sock, cmd:cmd, timeout:60);

if(!version || "not found" >< version || "@INC" >< version || version !~ "^[0-9.]+$")exit(0);

if(version_is_less(version: version, test_version: "2.27")) {
  security_hole(0);
}

ssh_close_connection();
exit(0);

