##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_sql_server_2000_activex_bof_vuln_900125.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Microsoft SQL Server 2000 sqlvdir.dll ActiveX Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation allows remote attackers to execute
 arbitrary code and failed attepts causes denial-of-service conditions.
 Impact Level : Application";

tag_solution = "No solution or patch is available as of 15th September, 2008.
 Information regarding this issue will be updated once the solution details
 are available. For updates check,
 http://www.microsoft.com/sqlserver";

tag_affected = "Microsoft SQL Server 2000 SP4 and prior on Windows (all)";

tag_insight = "Applications sqlvdir.dll ActiveX control is prone to a buffer-overflow
 vulnerability because it fails to bounds-check user-supplied data
 before copying it into an insufficiently sized buffer. The issue occurs
 when excessive amounts of data to the Control() method is passed.";


tag_summary = "The host is running Microsoft SQL Server, which is prone to
 buffer-overflow vulnerability.";


if(description)
{
 script_id(900125);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
 script_cve_id("CVE-2008-4110");
 script_bugtraq_id(31129);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_name("Microsoft SQL Server 2000 sqlvdir.dll ActiveX Buffer Overflow Vulnerability");
 script_summary("Check for vulnerable version of Microsoft SQL Server 2000");
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
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://support.microsoft.com/kb/240797");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/496232");
 script_xref(name : "URL" , value : "http://www.juniper.net/security/auto/vulnerabilities/vuln31129.html");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 include("smb_nt.inc");

 msSqlPort = 1433;

 if(!get_port_state(msSqlPort)){
        exit(0);
 }

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 msSqlVer = registry_get_sz( key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                     "\Uninstall\Microsoft SQL Server 2000",
                                  item:"DisplayVersion");

 if(egrep(pattern:"^([0-7]\..*|8\.(0?0(\.([0-9]?[0-9]|1[0-8][0-9]|19[0-4]))?" +
                  "))$", string:msSqlVer)){
      security_hole(0);
 }
