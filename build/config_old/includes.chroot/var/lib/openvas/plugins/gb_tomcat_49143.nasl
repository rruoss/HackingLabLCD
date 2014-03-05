###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tomcat_49143.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apache Commons Daemon 'jsvc' Information Disclosure Vulnerability
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
tag_summary = "Apache Commons Daemon is prone to a remote information-disclosure
vulnerability that affects the 'jsvc' library.

Remote attackers can exploit this issue to gain access to files and
directories owned by the superuser, through applications using the
affected library. This allows attackers to obtain sensitive
information that may aid in further attacks.

Note: This issue affects applications running on Linux operating
      systems only.

Versions prior to Commons Daemon 1.0.7 are vulnerable.

The following Apache Tomcat versions which use the affected library
are vulnerable:

Tomcat 7.0.0 through 7.0.19 Tomcat 6.0.30 through 6.0.32 Tomcat 5.5.32
through 5.5.33";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103202";
CPE = "cpe:/a:apache:tomcat";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)");
 script_bugtraq_id(49143);
 script_cve_id("CVE-2011-2729");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Apache Commons Daemon 'jsvc' Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49143");
 script_xref(name : "URL" , value : "http://mail-archives.apache.org/mod_mbox/tomcat-announce/201108.mbox/%3C4E45221D.1020306@apache.org%3E");
 script_xref(name : "URL" , value : "http://commons.apache.org/daemon/");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-5.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-6.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-7.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/");
 script_xref(name : "URL" , value : "http://commons.apache.org/daemon/jsvc.html");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installe Tomcat version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_apache_tomcat_detect.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("ApacheTomcat/installed");
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

if(report_paranoia < 2) exit(0); # this nvt is pront to FP
if (host_runs("Linux") == "no") exit(0); #  This issue affects applications running on Linux operating systems only.

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
if(!isnull(vers)) {

  if(version_in_range(version:vers, test_version:"7.0",    test_version2:"7.0.19") ||
     version_in_range(version:vers, test_version:"6.0.30", test_version2:"6.0.32") ||
     version_in_range(version:vers, test_version:"5.5.32", test_version2:"5.5.33")) {
    
      security_warning(port:port);
      exit(0);

  }

}  

exit(0);
