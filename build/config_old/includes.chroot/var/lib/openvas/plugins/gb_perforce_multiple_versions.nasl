###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perforce_multiple_versions.nasl 14 2013-10-27 12:33:37Z jan $
#
# Perforce Multiple Vulnerabilities
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
tag_summary = "Perforce Server is prone to Multiple Vulnerabilities.

1. A security-bypass vulnerability.
Attackers may exploit the issue to bypass certain security
restrictions and perform unauthorized actions.

2. A session-hijacking vulnerability. 
An attacker can exploit this issue to gain access to the affected
application.";


if (description)
{
 script_id(100521);
 script_version("$Revision: 14 $");
 script_cve_id("CVE-2010-0934");
 script_bugtraq_id(38589,38595);
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-09 14:33:24 +0100 (Tue, 09 Mar 2010)");
 script_name("Perforce Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38589");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38595");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56738");
 script_xref(name : "URL" , value : "http://www.perforce.com/perforce/products/p4web.html");
 script_xref(name : "URL" , value : "http://resources.mcafee.com/forms/Aurora_VDTRG_WP");

 script_description(desc);
 script_summary("Determine if installed Perforce Server is vulnerable");
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
  if(version_is_equal(version: version[2], test_version: "2009.2") ||
     version_is_equal(version: version[2], test_version: "2007.2") ||
     version_is_equal(version: version[2], test_version: "2007.1") ||
     version_is_equal(version: version[2], test_version: "2006.2") ||
     version_is_equal(version: version[2], test_version: "2006.1")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
