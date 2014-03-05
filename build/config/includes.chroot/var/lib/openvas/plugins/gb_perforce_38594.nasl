###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perforce_38594.nasl 14 2013-10-27 12:33:37Z jan $
#
# Perforce Socket Hijacking Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "Perforce is prone to a vulnerability that allows attackers to
hijack sockets.

NOTE: For an exploit to succeed, the underlying operating system must
      allow rebinding of a port.";


if (description)
{
 script_id(100520);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-09 14:33:24 +0100 (Tue, 09 Mar 2010)");
 script_bugtraq_id(38594);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Perforce Socket Hijacking Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38594");
 script_xref(name : "URL" , value : "http://www.perforce.com/perforce/products/p4d.html");
 script_xref(name : "URL" , value : "http://resources.mcafee.com/forms/Aurora_VDTRG_WP");

 script_description(desc);
 script_summary("Determine if installed Perforce Server is Vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("perforce_detect.nasl");
 script_require_ports("Services/perforce", 1666);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/perforce");
if(!port)exit(0);
if (!get_tcp_port_state(port))exit(0);

if(!vers = get_kb_item(string("perforce/", port, "/version")))exit(0);
if(!isnull(vers)) {

  if(!version = split(vers, sep: "/", keep: 0))exit(0);
  if(version[2] >< "2008.1") {
    if(version_is_equal(version: version[3], test_version: "160022")) {
      VULN = TRUE;
    }
  } 
  else if(version[2] >< "2009.2" || version[2] >< "2007.3") {
     VULN = TRUE;
  }

  if(VULN) {
      security_warning(port:port);
      exit(0);
  }
}

exit(0);
