###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_38533.nasl 14 2013-10-27 12:33:37Z jan $
#
# OpenSSL 'dtls1_retrieve_buffered_fragment()' Remote Denial of Service Vulnerability
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
tag_summary = "OpenSSL is prone to a denial-of-service vulnerability caused
by a NULL-pointer dereference.

According to its banner, OpenVAS has discovered that the remote Webserver is
using a version prior to OpenSSL 0.9.8n which is vulnerable.

An attacker can exploit this issue to crash the affected application,
denying service to legitimate users.

OpenSSL versions 0.9.8m and prior are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100588);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-20 13:41:39 +0200 (Tue, 20 Apr 2010)");
 script_bugtraq_id(38533);
 script_cve_id("CVE-2010-0433");

 script_name("OpenSSL 'dtls1_retrieve_buffered_fragment()' Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38533");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=567711");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=569774");
 script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/03/03/5");
 script_xref(name : "URL" , value : "http://cvs.openssl.org/chngview?cn=19374");
 script_xref(name : "URL" , value : "http://www.openssl.org");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/510726");

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed OpenSSL version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);

if(!banner || "OpenSSL/" >!< banner)exit(0);

version = eregmatch(pattern: "OpenSSL/([^ ]+)", string: banner);
if(isnull(version[1]))exit(0);

vers = version[1];

vers = ereg_replace(string:vers, pattern:"([a-z]$)", replace:".\1");

if(vers =~ "^0\.9\.") {

  if(!isnull(vers)) {

    if(version_is_less(version: vers, test_version: "0.9.8.n")) {
        security_warning(port:port);
        exit(0);
    }

  }
}

exit(0);
