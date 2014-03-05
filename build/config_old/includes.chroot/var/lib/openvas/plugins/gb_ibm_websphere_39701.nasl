###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_39701.nasl 14 2013-10-27 12:33:37Z jan $
#
# IBM WebSphere Application Server SIP Logging Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Uodated By: Antu sanadi <santu@secpod.com> on 2010-05-11
#  - Added the related CVE's
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
tag_summary = "IBM WebSphere Application Server (WAS) is prone to an information-
disclosure vulnerability.

A local authenticated attacker can exploit this issue to gain access
to sensitive information; this may aid in further attacks.

Versions prior to WAS 7.0.0.11 and 6.1.0.31 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100609);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)");
 script_cve_id("CVE-2010-1650", "CVE-2010-1651");
 script_bugtraq_id(39701);
 script_name("IBM WebSphere Application Server SIP Logging Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39701");
 script_xref(name : "URL" , value : "http://www-306.ibm.com/software/websphere/#");

 script_tag(name:"cvss_base", value:"1.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Low");
 script_description(desc);
 script_summary("Determine if installed WebSphere Application Server version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_ibm_websphere_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

if(!vers = get_kb_item(string("www/", port,"/websphere_application_server")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_in_range(version: vers, test_version: "7", test_version2: "7.0.0.10") ||
     version_in_range(version: vers, test_version: "6.1", test_version2: "6.1.0.30")) {

       security_note(port:port);
       exit(0);
  }
}

exit(0);
