# OpenVAS Vulnerability Test
# $Id: eftp_directory_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: EFTP tells if a given file exists
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# starting from guild_ftp.nasl
#
# Copyright:
# Copyright (C) 2001 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote FTP server can be used to determine if a given
file exists on the remote host or not, by adding dot-dot-slashes
in front of them. 

For instance, it is possible to determine the presence
of \autoexec.bat by using the command SIZE or MDTM on
../../../../autoexec.bat

An attacker may use this flaw to gain more knowledge about
this host, such as its file layout. This flaw is specially
useful when used with other vulnerabilities.";

tag_solution = "update your EFTP server to 2.0.8.348 or change it";

if(description)
{
  script_id(10933);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3333);
  script_cve_id("CVE-2001-1109");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "EFTP tells if a given file exists";
 
 script_name(name);
 
 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;





 script_description(desc);
 
 summary = "EFTP directory traversal";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2001 Michel Arboi");
 family = "FTP";

 script_family(family);
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");
 script_require_keys("Settings/ThoroughTests");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
 exit(0);
}

#
include("ftp_func.inc");
include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

cmd[0] = "SIZE";
cmd[1] = "MDTM";

port = get_kb_item("Services/ftp");
if(!port)port = 21;
login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
# login = "ftp"; pass = "test@test.com";

if(get_port_state(port))
{
 vuln=0; tested=0;
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(login)
  {
   if(ftp_authenticate(socket:soc, user:login, pass:pass))
   {
    tested=tested+1;
    for (i = 0; cmd[i]; i = i + 1)
    {
     req = string(cmd[i], " ../../../../../../autoexec.bat\r\n");
     send(socket:soc, data:req);
     r = ftp_recv_line(socket:soc);
     if("230 " >< r) vuln=vuln+1;
    }
   }
   else
   {
    # We could not log in ou could not download autoexec.
    # We'll just attempt to grab the banner and check for version
    # <= 2.0.7
    # I suppose that any version < 2 is vulnerable...
    r = ftp_recv_line(socket:soc);
    if(egrep(string:r, pattern:".*EFTP version ([01]|2\.0\.[0-7])\..*"))
     vuln = 1;
   }
  }
  close(soc);
  if (vuln)
  {
   if (tested)
   {
    security_hole(port);
   }
   else
   {
    rep="The remote FTP server may be used to determine if a given
file exists on the remote host or not, by adding dot-dot-slashes
in front of them. 

For instance, it should be possible to determine the presence
of \autoexec.bat by using the command SIZE or MDTM on
../../../../autoexec.bat

An attacker may use this flaw to gain more knowledge about
this host, such as its file layout. This flaw is specially
useful when used with other vulnerabilities.

*** OpenVAS could not test the presence of autoexec.bat
*** and solely relied on the version number of your
*** server, so this may be a false positive.

Solution: update your FTP server and change it";
    security_hole(port:port, data:rep);
   }
   exit(0);
  }
 }
}

#
# NB: This server is also vulnerable to another attack.
#
# Date:  Thu, 13 Dec 2001 12:59:43 +0200
# From: "Ertan Kurt" <ertank@olympos.org>
# Affiliation: Olympos Security
# To: bugtraq@securityfocus.com
# Subject: EFTP 2.0.8.346 directory content disclosure
#
# It is possible to see the contents of every drive and directory of
# vulnerable server.
# A valid user account is required to exploit this vulnerability.
# It works both with encryption and w/o encryption.
# Here's how it's done:
# the user is logged in to his home directory (let's say d:\userdir)
# when the user issues a CWD to another directory server returns
# permission denied.
# But, first changing directory to "..." (it will chdir to d:\userdir\...)
# then issuing a CWD to "\" will say permission denied but it will
# successfully change to root directory of the current drive.
# And everytime we want to see a dir's content, we first CWD to our
# home directory and then CWD ...  and then CWD directly to desired
# directory (CWD c:/ or c:/winnt etc)
# 
# So it is possible to see directory contents but i did not test to see
# if there is a possible way to get/put files.
#
