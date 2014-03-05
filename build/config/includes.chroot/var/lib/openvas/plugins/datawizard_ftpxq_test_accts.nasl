# OpenVAS Vulnerability Test
# $Id: datawizard_ftpxq_test_accts.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Tries to read a file via FTPXQ.
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
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
tag_summary = "The remote FTP server has one or more default test accounts. 

Description :

The version of DataWizard FTPXQ that is installed on the remote host
has one or more default accounts setup which can allow an attacker to
read and/or write arbitrary files on the system.";

tag_solution = "Disable or change the password for any unnecessary user accounts.";

desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if (description)
{
	# set script identifiers
	script_id(80053);;
	script_version("$Revision: 16 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"6.4");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
    script_tag(name:"risk_factor", value:"High");
	
	script_cve_id("CVE-2006-5569");
	script_bugtraq_id(20721);
	script_xref(name:"OSVDB", value:"30010");

	name = "DataWizard FTPXQ Default Accounts";
	summary = "Tries to read a file via FTPXQ.";

	script_name(name);
	script_description(desc);
	script_summary(summary);

	script_category(ACT_GATHER_INFO);
	script_copyright("This script is Copyright (C) 2006 Justin Seitz");
	
	script_family("FTP");

	script_dependencies("ftpserver_detect_type_nd_version.nasl");
	script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
	script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://attrition.org/pipermail/vim/2006-November/001107.html");
	exit(0);

}

include("ftp_func.inc");
include("global_settings.inc");

#
#	Verify we can talk to the FTP server, if not exit
#
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (!get_port_state(port)) exit(0);


banner = get_ftp_banner(port:port);
if (!banner || "FtpXQ FTP" >!< banner) exit(0);

#
#
#		Now let's attempt to login with the default test account.
#
#

soc = open_sock_tcp(port);
if(!soc) exit(0);

n = 0;
acct[n] = "anonymous";
pass[n] = "";
n++;
acct[n] = "test";
pass[n] = "test";

file = '\\boot.ini';
contents = "";
info = "";
for (i=0; i<max_index(acct); i++) {
  login = acct[i];
  password = pass[i];

  if (ftp_authenticate(socket:soc, user:login, pass:password)) {
    info += "  " + login + "/" + password + '\n';

    if (strlen(contents) == 0) {
      #
      #
      #	We have identified that we have logged in with the account, let's try to read boot.ini.
      #
      # 
      port2 = ftp_pasv(socket:soc);
      if (!port2) exit(0);
      soc2 = open_sock_tcp(port2, transport:ENCAPS_IP);
      if (!soc2) exit(0);

      attackreq = string("RETR ", file);
      send(socket:soc, data:string(attackreq, "\r\n"));
      attackres = ftp_recv_line(socket:soc);
      if (egrep(string:attackres, pattern:"^(425|150) ")) {
        attackres2 = ftp_recv_data(socket:soc2);

        # There's a problem if it looks like a boot.ini.
        if ("[boot loader]" >< attackres2)
          contents = attackres2;
      }
    }
  }
}

if (info) {
  info = string("The remote version of FTPXQ has the following\n",
    "default accounts enabled :\n\n",
    info);

  if ("test/test" >< info)
    info = string(info, "\n",
      "Note that the test account reportedly allows write access to the entire\n",
      "filesystem, although OpenVAS did not attempt to verify this.\n");

  if (contents)
    info = string(info, "\n",
      "In addition, OpenVAS was able to use one of the accounts to read ", file, " :\n",
      "\n",
      contents);

  report = string(desc,"\n\nPlugin Output\n\n", info);		
  security_hole(data:report, port:port);
}
ftp_close(socket:soc);
