###############################################################################
# OpenVAS Vulnerability Test
# $Id: dopewars_server_36606.nasl 15 2013-10-27 12:49:54Z jan $
#
# Dopewars Server 'REQUESTJET' Message Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "Dopewars is prone to a denial-of-service vulnerability that affects
the server part of the application.

An attacker can exploit this issue to crash the affected application,
denying service to legitimate users.

This issue affects Dopewars 1.5.12; other versions may also be
affected.";


tag_solution = "Fixes are available in the SVN repository. Please see the references
for details.";

if (description)
{
 script_id(100305);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-15 20:14:59 +0200 (Thu, 15 Oct 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2009-3591");
 script_bugtraq_id(36606);
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Dopewars Server 'REQUESTJET' Message Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36606");
 script_xref(name : "URL" , value : "http://dopewars.sourceforge.net/");
 script_xref(name : "URL" , value : "http://dopewars.svn.sourceforge.net/viewvc/dopewars?view=rev&amp;revision=1033");

 script_description(desc);
 script_summary("Determine if Dopewars is prone to a dos vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown", 7902);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("version_func.inc");

port = 7902;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("OpenVAS^^Ar1111111\n^^AcOpenVAS\n");
send(socket:soc, data:req);
buf = recv(socket:soc, length:50);

if(!buf)exit(0);

if("^" >< buf[0]) {
  if(!version = eregmatch(pattern:"\^Ak([0-9.]+)\^",string:buf))exit(0);
  if(isnull(version[1]))exit(0);

  if(version_is_equal(version:version[1], test_version: "1.5.12")) {
   security_warning(port:port);
   exit(0);
  }  
}
exit(0);

  
