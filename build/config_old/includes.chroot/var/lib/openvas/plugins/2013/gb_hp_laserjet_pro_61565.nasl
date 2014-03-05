###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_laserjet_pro_61565.nasl 11 2013-10-27 10:12:02Z jan $
#
# Multiple HP LaserJet Pro Printers  Unspecified Information Disclosure Vulnerability
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
tag_impact = "The vulnerability could be exploited remotely to gain unauthorized access to data.
Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103757";

tag_insight = "The hidden URL '/dev/save_restore.xml' contains a hex representation
of the admin password in plaintext and no authentication is needed to access this
site.";


tag_affected = "
HP LaserJet Pro P1102w 
HP LaserJet Pro P1606dn
HP LaserJet Pro M1212nf MFP
HP LaserJet Pro M1213nf MFP
HP LaserJet Pro M1214nfh MFP
HP LaserJet Pro M1216nfh MFP
HP LaserJet Pro M1217nfw MFP
HP LaserJet Pro M1218nfs MFP
HP LaserJet Pro CP1025nw";

tag_summary = "Multiple HP LaserJet Pro Printers are prone to an information-disclosure
vulnerability.";

tag_solution = "Updates are available.";

tag_vuldetect = "Request /dev/save_restore.xml and read the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61565);
 script_cve_id("CVE-2013-4807");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
 script_version ("$Revision: 11 $");

 script_name("Multiple HP LaserJet Pro Printers  Unspecified Information Disclosure Vulnerability");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61565");
 script_xref(name:"URL", value:"http://www.hp.com/");
 
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-12 16:59:44 +0200 (Mon, 12 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read /dev/save_restore.xml");
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

url = '/dev/save_restore.xml';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<name>e_HttpPassword</name>" >< buf) {

  security_hole(port:port);
  exit(0);

}  

exit(0);

