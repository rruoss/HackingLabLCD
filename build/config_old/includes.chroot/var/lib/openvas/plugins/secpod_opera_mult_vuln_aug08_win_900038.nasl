##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_mult_vuln_aug08_win_900038.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Opera Web Browser Multiple Security Vulnerabilities Aug-08 (Win)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_impact = "Remote exploitation will allow browser to crash, can potentially
        execute arbitrary code, cross site scripting attacks, and can even change 
        the address field to the address of the malicious web page to mislead a user.
 Impact Level : Application";

tag_solution = "Upgrade to Opera version 9.52,
 http://www.opera.com/download/";

tag_affected = "Opera Version 9.51 and prior versions on Windows (All)";

tag_insight = "Multiple vulnerabilities exists in Opera Browser,
	- Sites can change framed content on other sites
	- Startup crash can allow execution of arbitrary code
	- Custom shortcuts can pass the wrong parameters to applications
	- Insecure pages can show incorrect security information
	- Feed links can link to local files
	- Feed subscription can cause the wrong page address to be displayed";


tag_summary = "The remote host is running Opera Web Browser, which is prone
 to multiple vulnerabilities.";


if(description)
{
 script_id(900038);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-4195");
 script_bugtraq_id(30768);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_name("Opera Web Browser Multiple Security Vulnerabilities Aug-08 (Win)");
 script_summary("Check for Opera Web Browser Version");
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Impact:
 " + tag_impact + "
 Affected Software/OS:
 " + tag_affected + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_dependencies("secpod_reg_enum.nasl", "secpod_opera_detection_win_900036.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/892/");
 script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/893/");
 script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/894/");
 script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/895/");
 script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/896/");
 script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/897/");
 script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/952/");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 if(!get_kb_item("SMB/WindowsVersion")){
 	exit(0);
 }

 if(egrep(pattern:"^([0-8]\..*|9\.([0-4]?[0-9]|5[01]))$",
	  string:get_kb_item("Opera/Win/Version"))){
	security_warning(0);
 }
