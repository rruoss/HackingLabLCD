###################################################################
# OpenVAS Vulnerability Test
#
# CA ARCserve Backup Multiple Buffer Overflow Vulnerabilities
#
# LSS-NVT-2010-003
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_solution = "The vendor released an advisory and updates to address these issues.
 Please see the references for more information.";
tag_summary = "Multiple stack-based buffer overflows in CA (Computer Associates) 
 BrightStor ARCserve Backup for Laptops and Desktops r11.0 through 
 r11.5 allow remote attackers to execute arbitrary code via a long 
 (1) username or (2) password to the rxrLogin command in rxRPC.dll, 
 or a long (3) username argument to the GetUserInfo function.";

if(description)
{
 script_id(102018);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-02 10:10:27 +0200 (Fri, 02 Apr 2010)");
 script_cve_id("CVE-2007-5003");
 script_bugtraq_id(24348);
 script_name("CA ARCserve Backup Multiple Bufffer Overflow Vulnerabilities");
 desc = "
 Summary:
 " + tag_summary + "

 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=156002");
 script_xref(name : "URL" , value : "http://research.eeye.com/html/advisories/published/AD20070920.html");
 script_description(desc);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_summary("Checks if version of CA ARCServe Backup is between r11.0 and r11.5");
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2010 LSS");
 script_family("Buffer overflow");
 script_dependencies("arcserve_backup_detect.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

arcserve_port = 1900;

if(!get_port_state(arcserve_port)) exit(0);

ver = get_kb_item(string("arcserve/", arcserve_port, "/version"));

if (!ver) exit(0);

if(eregmatch(pattern:"11\.[0-5]+\.[0-9]+",string:ver)) {
  security_hole(arcserve_port);
  exit(0);
}

exit(0);
