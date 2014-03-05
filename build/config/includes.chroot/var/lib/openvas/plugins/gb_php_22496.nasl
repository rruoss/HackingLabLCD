###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_22496.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP 5.2.0 and Prior Versions Multiple Vulnerabilities
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
tag_solution = "The vendor has released updates to address these issues. Contact the
vendor for details on obtaining and applying the appropriate updates.

Please see the advisories for more information.";

tag_summary = "PHP 5.2.0 and prior versions are prone to multiple security
vulnerabilities. Successful exploits could allow an attacker to write
files in unauthorized locations, cause a denial-of-service condition,
and potentially execute code.

These issues are reported to affect PHP 4.4.4 and prior versions in
the 4 branch, and 5.2.0 and prior versions in the 5 branch; other
versions may also be vulnerable.";


if (description)
{
 script_id(100606);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)");
 script_bugtraq_id(22496);
 script_cve_id("CVE-2007-0905","CVE-2007-0906","CVE-2007-0907","CVE-2007-0908","CVE-2007-0909","CVE-2007-0910");

 script_name("PHP 5.2.0 and Prior Versions Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/22496");
 script_xref(name : "URL" , value : "http://support.avaya.com/elmodocs2/security/ASA-2007-136.htm");
 script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php#5.2.1");
 script_xref(name : "URL" , value : "http://www.php.net/releases/5_2_1.php");
 script_xref(name : "URL" , value : "http://support.avaya.com/elmodocs2/security/ASA-2007-101.htm");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2007-0076.html");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2007-0081.html#Red%20Hat%20Linux%20Advanced%20Workstation%202.1%20for%20the%20Itanium%20Processor");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2007-0082.html");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2007-0089.html");
 script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_44_php.html");

 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed php version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("php/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_kb_item("www/" + port + "/PHP")) {

    if(version_in_range(version: vers, test_version: "4",test_version2:"4.4.4")) {
        security_hole(port:port);
        exit(0);
    }

    if(version_in_range(version: vers, test_version: "5", test_version2:"5.2.0")) {
        security_hole(port:port);
        exit(0);
    }
}

exit(0);
