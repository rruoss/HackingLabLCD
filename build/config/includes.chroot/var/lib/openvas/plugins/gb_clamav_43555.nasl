###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_43555.nasl 14 2013-10-27 12:33:37Z jan $
#
# ClamAV 'find_stream_bounds()' PDF File Processing Denial Of Service Vulnerability
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
tag_summary = "ClamAV is prone to a denial-of-service vulnerability because
it fails to properly bounds-check specially crafted PDF files.

An attacker can exploit this issue to cause denial-of-service
conditions. Due to the nature of this issue, arbitrary code execution
may be possible; this has not been confirmed.

ClamAV 0.96.2 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100830);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-29 12:56:18 +0200 (Wed, 29 Sep 2010)");
 script_bugtraq_id(43555);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3434");

 script_name("ClamAV 'find_stream_bounds()' PDF File Processing Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43555");
 script_xref(name : "URL" , value : "http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=dc5143b4669ae39c79c9af50d569c28c798f33da");
 script_xref(name : "URL" , value : "https://wwws.clamav.net/bugzilla/show_bug.cgi?id=2226");
 script_xref(name : "URL" , value : "http://www.clamav.net/");
 script_xref(name : "URL" , value : "http://comments.gmane.org/gmane.comp.security.oss.general/3547");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed ClamAV version is vulnerable");
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

if(version_is_equal(version:ver, test_version:"0.96.2")){
    security_hole(port:port);
    exit(0);
}

exit(0);

