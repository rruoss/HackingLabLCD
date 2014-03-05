##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_python_mult_vuln_lin_900106.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Python Multiple Vulnerabilities (Linux)
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
tag_impact = "Successful exploitation could potentially causes attackers to
        execute arbitrary code or create a denial of service condition.
 Impact Level : Application";

tag_solution = "Fix is available in the SVN repository,
 http://svn.python.org";

tag_affected = "Python 2.5.2 and prior on Linux (All).";

tag_insight = "The flaws exists due to integer overflow in,
        - hashlib module, which can lead to an unreliable cryptographic digest 
          results.
        - the processing of unicode strings.
        - the PyOS_vsnprintf() function on architectures that do not have a 
          vsnprintf() function.
        - the PyOS_vsnprintf() function when passing zero-length strings can 
          lead to memory corruption.";


tag_summary = "The host is installed Python, which is prone to multiple vulnerabilities.

 This NVT has been replaced by NVT gb_CESA-2009_1176_python_centos5_i386.nasl
 (OID:1.3.6.1.4.1.25623.1.0.880881), gb_CESA-2009_1178_python_centos3_i386.nasl
 (OID:1.3.6.1.4.1.25623.1.0.880715).";

if(description)
{
 script_id(900106);
 script_version("$Revision: 16 $");
 script_tag(name:"deprecated", value:TRUE);
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(30491);
 script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142",
		"CVE-2008-3143","CVE-2008-3144");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_name("Python Multiple Vulnerabilities (Linux)");
 script_summary("Check for vulnerable version of Pyhton");
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
 script_dependencies("gather-package-list.nasl");
 script_require_keys("ssh/login/uname");
 script_xref(name : "URL" , value : "http://bugs.python.org/issue2588");
 script_xref(name : "URL" , value : "http://bugs.python.org/issue2589");
 script_xref(name : "URL" , value : "http://bugs.python.org/issue2620");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}

exit(66); ## This NVT is deprecated as addressed in gb_CESA-2009_1176_python_centos5_i386.nasl
          ## gb_CESA-2009_1178_python_centos3_i386.nasl

 include("ssh_func.inc");

 if("Linux" >!< get_kb_item("ssh/login/uname")){
        exit(0);
 }

 foreach item (get_kb_list("ssh/*/rpms"))
 {
        if("python" >< item)
        {
                if(egrep(pattern:"python-.*~([01]\..*|2\.([0-4]\..*|5\.[0-2]))[^.0-9]",
			 string:item)){
                        security_hole(0); 
                }
		exit(0);
        }
 }

 sock = ssh_login_or_reuse_connection();
 if(!sock){
        exit(0);
 }

 pyVer = ssh_cmd(socket:sock, cmd:"python -V", timeout:timeout);
 ssh_close_connection();

 if(!pyVer){
        exit(0);
 }

 if(egrep(pattern:"^Python ([01]\..*|2\.([0-4]\..*|5\.[0-2]))$", string:pyVer)){
        security_hole(0);
 }
