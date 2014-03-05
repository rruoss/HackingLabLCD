# OpenVAS Vulnerability Test
# $Id: libpng_CB-A08-0064.nasl 16 2013-10-27 13:09:52Z jan $
# Description: libpng vulnerability
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
tag_summary = "The remote host is probably affected by the vulnerabilities described in
CVE-2008-1382

Impact
      libpng 1.0.6 through 1.0.32, 1.2.0 through 1.2.26,
      and 1.4.0beta01 through 1.4.0beta19 allows context-dependent
      attackers to cause a denial of service (crash) and possibly
      execute arbitrary code via a PNG file with zero length
      unknown chunks, which trigger an access of uninitialized
      memory.";

tag_solution = "All users should upgrade to the latest libpng version of their Linux Distribution.";

# $Revision: 16 $

if(description)
{

 script_id(90021);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-03 22:30:27 +0200 (Wed, 03 Sep 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2008-1382");
 name = "libpng vulnerability";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1382");

 script_description(desc);
 summary = "Determines the Version of libpng";
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

local_var sec_proto, r;

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

sec_proto = "libpng";
r = find_bin(prog_name:"libpng-config", sock:sock);
foreach binary_name (r) {
  binary_name = chomp(binary_name);
  ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"([0-9\.]+)");
  if(ver != NULL) {
    if(version_is_less(version:ver[0], test_version:"1.0.32") ) {
      security_hole(port:0, proto:sec_proto);
      report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
      security_hole(port:0, proto:sec_proto, data:report);
    } else {
      if(version_is_greater_equal(version:ver[0], test_version:"1.2.0") &&
         version_is_less(version:ver[0], test_version:"1.2.27") ) {
        security_hole(port:0, proto:sec_proto);
        report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
        security_hole(port:0, proto:sec_proto, data:report);
      } else {
        if(version_is_equal(version:ver[0], test_version:"1.4.0") ) {
          ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"(beta..)");
          if(ver != NULL) {
            if(version_is_greater_equal(version:ver[0], test_version:"beta01") && 
               version_is_less(version:ver[0], test_version:"beta20") ) {
              security_hole(port:0, proto:sec_proto);
              report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
              security_hole(port:0, proto:sec_proto, data:report);
            }
          }
        }
      }
    }
  }
}

exit(0);
