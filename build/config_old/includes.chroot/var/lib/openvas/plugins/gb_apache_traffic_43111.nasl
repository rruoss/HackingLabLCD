###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_traffic_43111.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache Traffic Server Remote DNS Cache Poisoning Vulnerability
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
tag_summary = "Apache Traffic Server is prone to a remote DNS cache-poisoning
vulnerability.

An attacker can exploit this issue to divert data from a legitimate
site to an attacker-specified site.

Successful exploits will allow the attacker to manipulate cache data,
potentially facilitating man-in-the-middle, site-impersonation, or denial-of-
service attacks.

Versions prior to Apache Traffic Server 2.0.1.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100797);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-10 15:25:30 +0200 (Fri, 10 Sep 2010)");
 script_bugtraq_id(43111);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2952");

 script_name("Apache Traffic Server Remote DNS Cache Poisoning Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43111");
 script_xref(name : "URL" , value : "https://issues.apache.org/jira/browse/TS-425");
 script_xref(name : "URL" , value : "http://www.nth-dimension.org.uk/pub/NDSA20100830.txt.asc");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Apache Traffic Server version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_apache_traffic_detect.nasl");
 script_require_ports("Services/http_proxy", 8080, 3128);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

     
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_kb_item("Services/http_proxy");
if(!port)port = 8080;
if(!get_port_state(port))exit(0);

if(!vers = get_kb_item(string("www/", port, "/apache_traffic_server")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "2.0.1")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

