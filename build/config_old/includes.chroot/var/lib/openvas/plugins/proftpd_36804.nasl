###############################################################################
# OpenVAS Vulnerability Test
# $Id: proftpd_36804.nasl 15 2013-10-27 12:49:54Z jan $
#
# ProFTPD mod_tls Module NULL Character CA SSL Certificate Validation Security Bypass Vulnerability
#
# Authors:
# Michael Meyer
#
# Updated to check ProFTPD version 1.3.3 before 1.3.3.rc2
#   - By Antu Sanadi <santu@secpod.com> On 2009/11/02
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "ProFTPD is prone to a security-bypass vulnerability because the
application fails to properly validate the domain name in a signed CA
certificate, allowing attackers to substitute malicious SSL
certificates for trusted ones.

Successful exploits allows attackers to perform man-in-the-
middle attacks or impersonate trusted servers, which will aid in
further attacks.

Versions prior to ProFTPD 1.3.2b and 1.3.3 to 1.3.3.rc1 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100316);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-26 10:02:32 +0100 (Mon, 26 Oct 2009)");
 script_bugtraq_id(36804);
 script_cve_id("CVE-2009-3639");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("ProFTPD mod_tls Module NULL Character CA SSL Certificate Validation Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36804");
 script_xref(name : "URL" , value : "http://bugs.proftpd.org/show_bug.cgi?id=3275");
 script_xref(name : "URL" , value : "http://www.proftpd.org");

 script_description(desc);
 script_summary("Determine if ProFTPD version is < 1.3.2b");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("secpod_proftpd_server_remote_detect.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(port)){
  exit(0);
}

version = get_kb_item("ProFTPD/Ver");
if(!isnull(version))
{
  if(version_is_less(version:version,  test_version:"1.3.2.b")||
     version_in_range(version:version, test_version:"1.3.3",test_version2:"1.3.3.rc1")){
      security_hole(port);
    }
}
