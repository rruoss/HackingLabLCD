# OpenVAS Vulnerability Test
# $Id: mozilla_CB-A08-0017.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Mozilla Firefox, Thunderbird, Seamonkey. Several vulnerabilitys (Lin)
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host is probable affected by the vulnerabilitys described in 
CVE-2008-0416, CVE-2007-4879, CVE-2008-1195, CVE-2008-1233,
CVE-2008-1234, CVE-2008-1235, CVE-2008-1236, CVE-2008-1237,
CVE-2008-1238, CVE-2008-1240, CVE-2008-1241 and more.


Impact
     Mozilla contributors moz_bug_r_a4, Boris Zbarsky, 
     and Johnny Stenback reported a series of vulnerabilities 
     which allow scripts from page content to run with elevated
     privileges. moz_bug_r_a4 demonstrated additional variants
     of MFSA 2007-25 and MFSA2007-35 (arbitrary code execution
     through XPCNativeWrapper pollution). Additional 
     vulnerabilities reported separately by Boris Zbarsky, 
     Johnny Stenback, and moz_bug_r_a4 showed that the browser
     could be forced to run JavaScript code using the wrong 
     principal leading to universal XSS and arbitrary code execution.
     And more...";

tag_solution = "All Users should upgrade to the latest versions of Firefox, Thunderbird or Seamonkey.";

# $Revision: 16 $

if(description)
{

 script_id(90014);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2008-1238","CVE-2008-1240","CVE-2008-1241");
 name = "Mozilla Firefox, Thunderbird, Seamonkey. Several vulnerabilitys (Lin)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-14.html");
script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0412");
script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0416");
script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1238");
script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1240");
script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1241");

 script_description(desc);
 summary = "Mozilla Firefox, Thunderbird, Seamonkey. Several vulnerabilitys";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
 family = "General";
 script_family(family);
 script_dependencies("ssh_authorization.nasl");
 script_mandatory_keys("login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The code starts here
#


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

r = find_bin(prog_name:"firefox", sock:sock);
foreach binary_name (r) {
  binary_name = chomp(binary_name);
  ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"([0-9\.]+)");
  if(ver != NULL) {
    if(version_is_less(version:ver[0], test_version:"2.0.0.14") ) {
      security_warning(port:0, proto:"Mozilla");
      report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
      security_warning(port:0, proto:"Mozilla", data:report);
    } 
  }
}
r = find_bin(prog_name:"thunderbird", sock:sock);
foreach binary_name (r) {
  binary_name = chomp(binary_name);
  ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"([0-9\.]+)");
  if(ver != NULL) {
    if(version_is_less(version:ver[0], test_version:"2.0.0.14") ) {
      security_warning(port:0, proto:"Mozilla");
      report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
      security_warning(port:0, proto:"Mozilla", data:report);
    } 
  }
}
r = find_bin(prog_name:"seamonkey", sock:sock);
foreach binary_name (r) {
  binary_name = chomp(binary_name);
  ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"([0-9\.]+)");
  if(ver != NULL) {
    if(version_is_less(version:ver[0], test_version:"1.1.9") ) {
      security_warning(port:0, proto:"Mozilla");
      report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
      security_warning(port:0, proto:"Mozilla", data:report);
    } 
  }
}

exit(0);
