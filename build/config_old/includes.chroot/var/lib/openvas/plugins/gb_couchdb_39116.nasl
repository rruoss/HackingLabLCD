###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_couchdb_39116.nasl 14 2013-10-27 12:33:37Z jan $
#
# CouchDB Message Digest Verification Security Bypass Vulnerability
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
tag_summary = "CouchDB is prone to a security-bypass vulnerability because it
compares message digests using a variable time algorithm.

Successfully exploiting this issue allows an attacker to determine if
a forged digest is partially correct; repeated attacks will allow them
to determine specific, legitimate digests.

Versions prior to CouchDB 0.11 are vulnerable.";

tag_solution = "The vendor has released updates. Please see the references for
details.";

if (description)
{
 script_id(100572);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)");
 script_bugtraq_id(39116);
 script_cve_id("CVE-2010-0009");

 script_name("CouchDB Message Digest Verification Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39116");
 script_xref(name : "URL" , value : "http://couchdb.apache.org/");

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed CouchDB version is < 0.11");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_couchdb_detect.nasl");
 script_require_ports("Services/www", 5984);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

     
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:5984);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("couchdb/",port,"/version")))exit(0);

vers = version;

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "0.11")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

