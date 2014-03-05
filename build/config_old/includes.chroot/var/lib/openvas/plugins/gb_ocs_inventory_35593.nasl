###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ocs_inventory_35593.nasl 14 2013-10-27 12:33:37Z jan $
#
# OCS Inventory NG Agent 'Backend.pm' Perl Module Handling Code Execution Vulnerability
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
tag_summary = "OCS Inventory NG Agent is prone to a vulnerability that lets local
attackers execute arbitrary Perl code.

Local attackers can leverage this issue to execute arbitrary code via
the application's insecure Perl module search path. This may allow
attackers to elevate their privileges and compromise the application
or the underlying computer. Other attacks may also be possible.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100868);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-25 12:51:03 +0200 (Mon, 25 Oct 2010)");
 script_bugtraq_id(35593);
 script_cve_id("CVE-2009-0667");

 script_name("OCS Inventory NG Agent 'Backend.pm' Perl Module Handling Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_description(desc);
 script_summary("Determine if installed OCS Inventory NG Agent version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/35593");
 script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=506416");
 script_xref(name : "URL" , value : "http://www.ocsinventory-ng.org/");
 script_xref(name : "URL" , value : "http://www.ocsinventory-ng.org/index.php?mact=News,cntnt01,detail,0&amp;cntnt01articleid=144&amp;cntnt01returnid=64");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(vers = get_version_from_kb(port:port,app:"OCS_Inventory_NG")) {

  if(version_is_equal(version: vers, test_version: "0.0.9.2") ||
     version_is_equal(version: vers, test_version: "1.00")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
