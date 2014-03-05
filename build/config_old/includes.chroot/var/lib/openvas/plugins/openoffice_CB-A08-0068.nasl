# OpenVAS Vulnerability Test
# $Id: openoffice_CB-A08-0068.nasl 16 2013-10-27 13:09:52Z jan $
# Description: OpenOffice.org <= 2.4.1 vulnerability (Lin)
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
CVE-2008-2152 or CVE-2008-3282 on 64-bit platform's

OpenOffice.org <= 2.4.1 vulnerability

Impact

   CVE-2008-2152
     Integer overflow in the rtl_allocateMemory function in
     sal/rtl/source/alloc_global.c in OpenOffice.org (OOo)
     2.0 through 2.4 allows remote attackers to execute
     arbitrary code via a crafted file that triggers a
     heap-based buffer overflow. 
   CVE-2008-3282
     Integer overflow in the rtl_allocateMemory function
     in sal/rtl/source/alloc_global.c in the memory allocator
     in OpenOffice.org (OOo) 2.4.1, on 64-bit platforms, allows
     remote attackers to cause a denial of service (application
     crash) or possibly execute arbitrary code via a crafted
     document, related to a 'numeric truncation error,' a
     different vulnerability than CVE-2008-2152.";

tag_solution = "All OpenOffice.org users should upgrade to the latest version.";

# $Revision: 16 $

if(description)
{

 script_id(90029);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-09 22:57:12 +0200 (Tue, 09 Sep 2008)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-2008-2152");
 name = "OpenOffice.org <= 2.4.1 vulnerability (Lin)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2152");
script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3282");

 script_description(desc);
 summary = "Determines OpenOffice.org <= 2.4.1 vulnerability";
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

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.90029";
SCRIPT_DESC = "OpenOffice.org at most 2.4.1 vulnerability (Lin)";


sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

sec_hole = 0;
sec_proto = "OpenOffice.org";
test_version = "2.4.9310";
ver = NULL;
r = NULL;

  l = find_file(file_name:"soffice.bin", sock:sock);
  if( isnull(l) ) {
    l = find_file(file_path:"/usr/lib/", file_name:"soffice.bin", sock:sock);
    if( isnull(l) ) {    
      l = find_file(file_path:"/usr/lib64/", file_name:"soffice.bin", sock:sock);
    }
  }
  if( ! isnull(l) ) {
    i = 0;
    foreach t (l) {
      if( "soffice.bin" >< t ) {
        p = chomp(ereg_replace(string:t, pattern:"soffice.bin", replace:""));
        if( !isnull(find_file(file_path:p, file_name:"versionrc", sock:sock)) ) {
          r[i++] =  p + "versionrc";
        }
      }
    }
    foreach file_name (r) {
      file_name = chomp(file_name);
      if(islocalhost()) { 
        arg = file_name;
      } else {
        arg = raw_string(0x22)+file_name+raw_string(0x22);
      }
      ver = get_bin_version(full_prog_name:"cat", version_argv:arg, ver_pattern:".+");
      if( ! isnull(ver) && !((ver[0] =~ "Vendor=Debian") && (ver[0] !~ "Ubuntu")) ) {
        version = ereg_replace(pattern:".+OOOBaseVersion=", string: ver[0], replace: "")+".";
        version = eregmatch(pattern:"([0-9]\.)+[0-9]+", string: version);
        build = ereg_replace(pattern:".+ProductBuildid=", string: ver[0], replace: "");
        build = eregmatch(pattern:"^[0-9]+", string: build);
        ver = version[0]+"."+build[0];
        set_kb_item(name: "OpenOffice.org/Build", value: ver);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value: ver, exp:"^([0-9.]+([a-z0-9]+)?)",base:"cpe:/a:openoffice:openoffice.org:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

        if( "/lib64" >< t ) {
          test_version = "2.4.9311";
        } else {
          test_version = "2.4.9310";          
        }
        if( version_is_less(version:ver, test_version:test_version) ) {
          if(sec_hole == 0) {
            security_hole(port:0, proto:sec_proto);
            sec_hole = 1;
          }
          security_hole(port:0, proto:sec_proto, data:string("\nFound : ") + 
                       (ereg_replace(string:file_name, pattern:"versionrc", replace:"soffice.bin")) +
                       " Build : " + ver + string("\n"));
        }  
      }
    }
  }
exit(0);
