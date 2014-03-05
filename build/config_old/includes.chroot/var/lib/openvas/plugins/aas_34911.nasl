###############################################################################
# OpenVAS Vulnerability Test
# $Id: aas_34911.nasl 15 2013-10-27 12:49:54Z jan $
#
# A-A-S Application Access Server Multiple Vulnerabilities
#
# Authors
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
tag_summary = "According to its version number, the remote version of A-A-S
  Application Access Server is prone to multiple security issues
  including a cross-site request-forgery vulnerability, an
  insecure-default-password vulnerability and an
  information-disclosure vulnerability.

  Attackers can exploit these issues to run privileged commands on the
  affected computer and gain unauthorized administrative access to the
  affected application and the underlying system.

  These issues affect version 2.0.48; other versions may also be
  affected.";


if (description)
{
 script_id(100197);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)");
 script_bugtraq_id(34911);
 script_cve_id("CVE-2009-1464","CVE-2009-1465","CVE-2009-1466");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("A-A-S Application Access Server Multiple Vulnerabilities");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if A-A-S Application Access Server Version == 2.0.48");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("aas_detect.nasl");
 script_require_ports("Services/www", 6262);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34911");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:6262);

if(!get_port_state(port))exit(0);

if(!vers = get_kb_item(string("www/", port, "/aas")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "2.0.48")) {
      security_hole(port:port);
      exit(0);
  }  

}

exit(0);
