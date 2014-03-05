###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_edirectory_57038.nasl 11 2013-10-27 10:12:02Z jan $
#
# Novell eDirectory Multiple Security Vulnerabilities
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
tag_summary = "Novell eDirectory is prone to following multiple remote
vulnerabilities:

1. A cross-site scripting vulnerability
2. A denial-of-service vulnerability
3. An information-disclosure vulnerability
4. A stack-based buffer-overflow vulnerability

Exploiting these issues could allow an attacker to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie-based authentication credentials,
disclose sensitive information, execute arbitrary code, cause a denial-of-
service condition. Other attacks are possible.

Novell eDirectory versions prior to 8.8.7.2 and 8.8.6.7 are
vulnerable.";


tag_solution = "An update is available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103630";
CPE = "cpe:/a:novell:edirectory";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57038);
 script_cve_id("CVE-2012-0428","CVE-2012-0429","CVE-2012-0430","CVE-2012-0432");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");

 script_name("Novell eDirectory Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57038");
 script_xref(name : "URL" , value : "http://www.novell.com/products/edirectory/");
 script_xref(name : "URL" , value : "http://www.novell.com/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-01-02 11:38:11 +0100 (Wed, 02 Jan 2013)");
 script_description(desc);
 script_summary("Check the version of Novell eDirectory");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("novell_edirectory_detect.nasl");
 script_require_ports("Services/ldap", 389);
 script_require_keys("eDirectory/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

version = get_kb_item("ldap/" + port + "/eDirectory");
if(isnull(version))exit(0);

if(version =~ "8\.8") {

  service_pack = eregmatch(pattern:"SP([0-9])+",string:version);
  if(!isnull(service_pack[1])) sp = int(service_pack[1]);

  major = eregmatch(pattern:"\(([0-9]+)\.([0-9]+)\)", string: version);
  if(!isnull(major[1])) mj = int(major[1]);

  if(!sp || sp < 6) hole = TRUE;
  if(sp == 6 && (!mj || mj < 20608)) hole = TRUE; 
  if(sp == 7 && (!mj || mj < 20703)) hole = TRUE;

}  

if(hole) {

  security_hole(port:port);
  exit(0);

}  

exit(99);


