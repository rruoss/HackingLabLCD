###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_50639.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apache HTTP Server 'ap_pregsub()' Function Local Denial of Service Vulnerability
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
tag_summary = "Apache HTTP Server is prone to a local denial-of-service
vulnerability because of a NULL-pointer dereference error or a
memory exhaustion.

Local attackers can exploit this issue to trigger a NULL-pointer
dereference or memory exhaustion, and cause a server crash, denying
service to legitimate users.

Note: To trigger this issue, 'mod_setenvif' must be enabled and the
      attacker should be able to place a malicious '.htaccess' file on
      the affected webserver.

Apache HTTP Server 2.0.x through 2.0.64 and 2.2.x through 2.2.21 are
vulnerable. Other versions may also be affected.";


if (description)
{
 script_id(103333);
 script_bugtraq_id(50639);
 script_cve_id("CVE-2011-4415");
 script_tag(name:"cvss_base", value:"1.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:P");
 script_version ("$Revision: 13 $");

 script_name("Apache HTTP Server 'ap_pregsub()' Function Local Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50639");
 script_xref(name : "URL" , value : "http://httpd.apache.org/");
 script_xref(name : "URL" , value : "http://www.halfdog.net/Security/2011/ApacheModSetEnvIfIntegerOverflow/");
 script_xref(name : "URL" , value : "http://www.gossamer-threads.com/lists/apache/dev/403775");

 script_tag(name:"risk_factor", value:"Low");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-15 12:33:51 +0100 (Tue, 15 Nov 2011)");
 script_description(desc);
 script_summary("Determine if installed Apache version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl", "secpod_apache_detect.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

httpdPort = get_http_port(default:80);
if(!httpdPort){
    exit(0);
}

version = get_kb_item("www/" + httpdPort + "/Apache");

if(version != NULL){

  if(version_in_range(version:version, test_version:"2.0",test_version2:"2.0.64") ||
     version_in_range(version:version, test_version:"2.2",test_version2:"2.2.21")) {
       security_note(port:httpdPort);
       exit(0);
  }

}

exit(0);
