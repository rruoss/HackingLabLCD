###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_42306.nasl 14 2013-10-27 12:33:37Z jan $
#
# OpenSSL 'ssl3_get_key_exchange()' Use-After-Free Memory Corruption Vulnerability
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
tag_summary = "OpenSSL is prone to a remote memory-corruption vulnerability.

According to its banner, OpenVAS has discovered that the remote
Webserver is using version 1.0.0a of OpenSSL which is vulnerable.

Successfully exploiting this issue may allow an attacker to execute
arbitrary code in the context of the application using the vulnerable
library. Failed exploit attempts will result in a denial-of-service
condition.

The issue affects OpenSSL 1.0.0a; other versions may also be affected.";


if (description)
{
 script_id(100751);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-10 14:55:08 +0200 (Tue, 10 Aug 2010)");
 script_bugtraq_id(42306);
 script_cve_id("CVE-2010-2939");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

 script_name("OpenSSL 'ssl3_get_key_exchange()' Use-After-Free Memory Corruption Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42306");
 script_xref(name : "URL" , value : "http://www.openssl.org");
 script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2010/Aug/84");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed OpenSSL version is vulnerabl");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

if(!isnull(vers)) {

  if(version_is_equal(version: vers, test_version: "1.0.0.a")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);