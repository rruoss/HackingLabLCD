###############################################################################
# OpenVAS Vulnerability Test
# $Id: default_ssh_credentials.nasl 13 2013-10-27 12:16:33Z jan $
#
# SSH Brute Force Logins with default Credentials 
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "It was possible to login into the remote host using default credentials.";

tag_solution = "Change the password as soon as possible.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary + "

 Solution:
 " + tag_solution;
if (description)
{

 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_tag(name:"risk_factor", value:"Critical");
 script_id(103239);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-09-06 14:38:09 +0200 (Tue, 06 Sep 2011)");
 script_name("SSH Brute Force Logins with default Credentials");
 script_description(desc);
 script_summary("Checks if login with default credentials is possible");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);

 script_timeout(600);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("default_credentials.inc");
include("ssh_func.inc");

port = get_kb_item("Services/ssh");

if(!port) port = 22;
if(!get_port_state(port))exit(0);
c = 0;

foreach credential (credentials) {

    credential = str_replace(string: credential, find:"\;", replace:"#sem#");

    user_pass = split(credential, sep:";",keep:FALSE);

    if(isnull(user_pass[0]) || isnull(user_pass[1]))continue;

    if(!soc = open_sock_tcp(port))exit(0);

    user = chomp(user_pass[0]);
    pass = chomp(user_pass[1]);

    user = str_replace(string: user, find:"#sem#", replace:";");
    pass = str_replace(string: pass, find:"#sem#", replace:";");

    if(tolower(pass) == "none")pass = "";

    login = ssh_login (socket:soc, login:user, password:pass, pub:NULL, priv:NULL, passphrase:NULL);

    ssh_supported_authentication = get_ssh_supported_authentication();
    if(ssh_supported_authentication =~ "^publickey$") {
      close(soc); 
      exit(0); # only pubkey is allowed, so dont continue trying with password
    }    

    if(login == 0) {
        c++;
        report = string(desc, "\n\n");
        report += string("It was possible to login with the following credentials ",
                         "<User>:<Password>\n\n", user, ":", pass, "\n");

        if(c >= 10) {
          report += '\nRemote host accept more then ' +  c + ' logins. This could indicate some error or some "broken" device.\nScanner stops testing for default logins at this point.\n';
        }  

        security_hole(port:port, data:report);
        if(c >= 10) {
          close(soc); 
          exit(0);
        }  
    }

    close(soc);
    usleep(50000);
}

