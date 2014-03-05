###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_40502.nasl 14 2013-10-27 12:33:37Z jan $
#
# OpenSSL Cryptographic Message Syntax Memory Corruption Vulnerability
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
Webserver is using a version prior to OpenSSL 0.9.8o/1.0.0a which is
vulnerable

An attacker can exploit this issue by supplying specially crafted
structures to a vulnerable application that uses the affected library.

Successfully exploiting this issue can allow the attacker to execute
arbitrary code. Failed exploit attempts will result in a denial-of-
service condition.

Versions of OpenSSL 0.9.h through 0.9.8n and OpenSSL 1.0.x prior to
1.0.0a are affected. Note that Cryptographic Message Syntax (CMS)
functionality is only enabled by default in OpenSSL versions 1.0.x.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100668);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-04 13:05:19 +0200 (Fri, 04 Jun 2010)");
 script_bugtraq_id(40502);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-0742");

 script_name("OpenSSL Cryptographic Message Syntax Memory Corruption Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40502");
 script_xref(name : "URL" , value : "http://www.openssl.org");
 script_xref(name : "URL" , value : "http://www.openssl.org/news/secadv_20100601.txt");

 script_tag(name:"risk_factor", value:"High");
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

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);

if(!banner || "OpenSSL/" >!< banner)exit(0);

version = eregmatch(pattern: "OpenSSL/([^ ]+)", string: banner);
if(isnull(version[1]))exit(0);

vers = version[1];

if (vers =~ "^0\.9\.([0-7]([^0-9]|$)|8([^a-z0-9]|[a-n]|$))" ||
    vers =~ "^1\.0\.0(-beta|$)") {

      security_hole(port:port);
      exit(0);

    }



exit(0);
