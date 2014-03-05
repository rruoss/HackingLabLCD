###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_50449.nasl 13 2013-10-27 12:16:33Z jan $
#
# Squid Proxy Caching Server CNAME Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "Squid proxy caching server is prone to a denial-of-service
vulnerability.

An attacker can exploit this issue to cause an affected application to
crash, denying service to legitimate users.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103320);
 script_cve_id("CVE-2011-4096");
 script_bugtraq_id(50449);
 script_version ("$Revision: 13 $");

 script_name("Squid Proxy Caching Server CNAME Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50449");
 script_xref(name : "URL" , value : "http://bugs.squid-cache.org/show_bug.cgi?id=3237");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=750316");
 script_xref(name : "URL" , value : "http://permalink.gmane.org/gmane.comp.security.oss.general/6144");
 script_xref(name : "URL" , value : "http://www.squid-cache.org/");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-01 08:00:00 +0100 (Sun, 01 Nov 2011)");
 script_description(desc);
 script_summary("Determine if installed Squid version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_squid_detect.nasl");
 script_require_ports("Services/www","Services/http_proxy",3128,8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

port = get_kb_item("Services/http_proxy");

if(!port){
  exit(0);
}

if(!vers = get_kb_item(string("www/", port, "/Squid")))exit(0);

if(!isnull(vers)) {

  if(version_is_equal(version:vers, test_version:"3.1.16")) {
    security_warning(port:port);
    exit(0);
  }  

}  

