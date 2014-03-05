###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gb_hp_openview_nnm_41829.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP OpenView Network Node Manager 'execvp_nc()' Code Execution Vulnerability
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
tag_summary = "HP OpenView Network Node Manager (OV NNM) is prone to a remote
code-execution vulnerability.

An attacker can exploit this issue to execute arbitrary code with SYSTEM-
level privileges. Successful exploits will completely compromise
affected computers.

The issue affects HP OpenView Network Node Manager versions 7.51 and
7.53 running on the Windows platform.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100786);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
 script_bugtraq_id(41829);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2703");

 script_name("HP OpenView Network Node Manager 'execvp_nc()' Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed HP OpenView Network Node Manager version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("os_fingerprint.nasl","secpod_hp_openview_nnm_detect.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41829");
 script_xref(name : "URL" , value : "http://www.exploit-db.com/moaub-6-hp-openview-nnm-webappmon-exe-execvp_nc-remote-code-execution/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/512543");
 script_xref(name : "URL" , value : "http://itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02286088");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-137/?utm_source=feedburner&amp;utm_medium=feed&amp;utm_campaign=Feed:+ZDI-Published-Advisories+%28Zero+Day+Initiative+Published+Advisories%29");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if (host_runs("windows") == "no") exit(0);

nnmPort = 7510;
if(!get_port_state(nnmPort)){
  exit(0);
}

nnmVer = get_kb_item(string("www/", nnmPort, "/HP/OVNNM/Ver"));
if(nnmVer != NULL)
{
  if(version_is_equal(version:nnmVer, test_version:"B.07.51") ||
     version_is_equal(version:nnmVer, test_version:"B.07.53")){
       security_hole(port:nnmPort);
       exit(0);
  }
}

exit(0);
