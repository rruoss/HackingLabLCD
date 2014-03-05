###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_40317.nasl 14 2013-10-27 12:33:37Z jan $
#
# ClamAV 'cli_pdf()' PDF File Processing Denial Of Service Vulnerability
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
tag_summary = "ClamAV is prone to a vulnerability that attackers can exploit
to cause denial-of-service conditions.

Versions prior to ClamAV 0.96.1 are vulnerable.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_id(100652);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-25 13:42:13 +0200 (Tue, 25 May 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2010-1639");
 script_bugtraq_id(40317);

 script_name("ClamAV 'cli_pdf()' PDF File Processing Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40317");
 script_xref(name : "URL" , value : "http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=f0eb394501ec21b9fe67f36cbf5db788711d4236");
 script_xref(name : "URL" , value : "https://wwws.clamav.net/bugzilla/show_bug.cgi?id=2016");
 script_xref(name : "URL" , value : "http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96.1");
 script_xref(name : "URL" , value : "http://www.clamav.net/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed ClamAV version is vulnerable.");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_clamav_detect_lin.nasl","gb_clamav_detect_win.nasl","gb_clamav_remote_detect.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/clamd");
if(!port)port = 0;

ver = get_kb_item("ClamAV/remote/Ver");
if(!ver) {
  ver = get_kb_item("ClamAV/Lin/Ver");
  if(!ver) {
    ver = get_kb_item("ClamAV/Win/Ver");
  }  
}  

if(!ver)exit(0);

if(version_is_less(version:ver, test_version:"0.96.1")){
    security_warning(port:port);
    exit(0);
}

exit(0);