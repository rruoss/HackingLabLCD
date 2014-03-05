###############################################################################
# OpenVAS Vulnerability Test
# $Id: squid_37522.nasl 14 2013-10-27 12:33:37Z jan $
#
# Squid Header-Only Packets Remote Denial of Service Vulnerability
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
tag_summary = "Squid is prone to a remote denial-of-service vulnerability.

An attacker can exploit this to issue to crash the affected
application, denying service to legitimate users.";


if (description)
{
 script_id(100412);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
 script_cve_id("CVE-2010-0308");
 script_bugtraq_id(37522);
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Squid Header-Only Packets Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37522");
 script_xref(name : "URL" , value : "http://events.ccc.de/congress/2009/Fahrplan//attachments/1483_26c3_ipv4_fuckups.pdf");
 script_xref(name : "URL" , value : "http://www.squid-cache.org/");

 script_description(desc);
 script_summary("Determine if Squid version is <= 3.1.5");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_squid_detect.nasl");
 script_require_ports("Services/www","Services/http_proxy",3128,8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_kb_item("Services/http_proxy");

if(!port){
  exit(0);
}

if(!vers = get_kb_item(string("www/", port, "/Squid")))exit(0);

if(!isnull(vers)) {
  if(version_is_less(version: vers, test_version: "3.1.5")) {
    security_warning(port: port);
    exit(0);
  }   
}  

exit(0);
