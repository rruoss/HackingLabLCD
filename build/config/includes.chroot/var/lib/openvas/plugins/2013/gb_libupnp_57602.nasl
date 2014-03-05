###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libupnp_57602.nasl 11 2013-10-27 10:12:02Z jan $
#
# libupnp Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "libupnp is prone to multiple buffer-overflow vulnerabilities because
it fails to perform adequate boundary checks on user-supplied data.

An attacker can exploit these issues to execute arbitrary code in the
context of the device that uses the affected library. Failed exploit
attempts will likely crash the application.

libupnp versions prior to 1.6.18 are affected.";


tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103658";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57602);
 script_cve_id("CVE-2012-5958","CVE-2012-5959","CVE-2012-5960","CVE-2012-5961","CVE-2012-5962","CVE-2012-5963","CVE-2012-5964","CVE-2012-5965");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");

 script_name("libupnp Multiple Buffer Overflow Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57602");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-02-06 15:35:24 +0100 (Wed, 06 Feb 2013)");
 script_description(desc);
 script_summary("Determine if installed libupnp version is < 1.6.18");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_upnp_detect.nasl");
 script_require_ports("Services/udp/upnp", "Services/www");
 script_require_keys("upnp/server");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

upnp_port = get_kb_item("Services/udp/upnp");
if(upnp_port) {

  server = get_kb_item("upnp/server");
  if(server && "sdk for upnp" >< tolower(server)) {

    version = eregmatch(pattern:"(Portable|Intel|WindRiver) SDK for UPnP devices/([0-9.]+)", string:server,icase:TRUE);
    if(!isnull(version[i2])) {
      if(version_is_less(version:version[2], test_version:"1.6.18")) {
        security_hole(port:upnp_port);
        exit(0);
      }
    }
  }
}

http_port = get_http_port(default:80);
if(!http_port)exit(0);

banner = get_http_banner(port:port);
if(!banner || "sdk for upnp" >!< tolower(banner))exit(0);

version = eregmatch(pattern:"(Portable|Intel|WindRiver) SDK for UPnP devices/([0-9.]+)", string:server,icase:TRUE);
if(isnull(version[2]))exit(0);

if(version_is_less(version:version[2], test_version:"1.6.18")) {
  security_hole(port:http_port);
  exit(0);
}

exit(0);
