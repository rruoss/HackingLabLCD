##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_itunes_prv_esc_vuln_900122.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Apple iTunes Local Privilege Escalation Vulnerability 
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will allow local users to obtain elevated
        privileges thus compromising the affected system.
 Impact Level : System";

tag_solution = "Upgrade to version 8.0,
 http://www.apple.com/itunes/download/";

tag_affected = "Apple iTunes versions prior to 8.0 on Windows";

tag_insight = "The flaw is due to integer overflow error in a third-party
        driver bundled with iTune.";


tag_summary = "The host is installed with Apple iTunes, which prone to privilege
 escalation vulnerability.";


if(description)
{
 script_id(900122);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
 script_bugtraq_id(31089);
 script_cve_id("CVE-2008-3636");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_name("Apple iTunes Local Privilege Escalation Vulnerability");
 script_summary("Check for vulnerable version of Apple iTunes");
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
 script_dependencies("secpod_reg_enum.nasl",
                     "secpod_apple_itunes_detection_win_900123.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Sep/1020839.html");
 script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2008/Sep/msg00001.html");
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

 if(egrep(pattern:"^([0-6]\..*|7\.[0-9](\..*)?)$", 
          string:get_kb_item("iTunes/Win/Ver"))){
        security_hole(0);
 }
