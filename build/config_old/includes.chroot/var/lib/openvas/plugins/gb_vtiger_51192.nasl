###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_51192.nasl 13 2013-10-27 12:16:33Z jan $
#
# vtiger CRM 'graph.php ' Script Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "vtiger CRM is prone to an authentication-bypass vulnerability.

An attacker can exploit this issue to bypass the authentication
process, download the database backup and modify configurations
settings.

vtiger CRM 5.2.1 is vulnerable; other versions may also be affected.";

tag_solution = "Vendor updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103374";
CPE = "cpe:/a:vtiger:vtiger_crm";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(51192);
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("vtiger CRM 'graph.php ' Script Authentication Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51192");
 script_xref(name : "URL" , value : "http://www.vtiger.com/");
 script_xref(name : "URL" , value : "http://francoisharvey.ca/2011/12/advisory-meds-2011-01-vtigercrm-anonymous-access-to-setting-module/");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-12-29 10:36:49 +0100 (Thu, 29 Dec 2011)");
 script_description(desc);
 script_summary("Determine if vtiger CRM is prone to an	authentication-bypass vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_vtiger_crm_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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

url = string(dir, "/graph.php?module=Settings&action=OrganizationConfig&parenttab=Settings"); 

if(http_vuln_check(port:port, url:url,pattern:"Company Details",extra_check:make_list("EditCompanyDetails","Company Name"))) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);

