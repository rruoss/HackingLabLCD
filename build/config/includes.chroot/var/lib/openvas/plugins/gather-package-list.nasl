# OpenVAS Vulnerability Test
# $Id: gather-package-list.nasl 61 2013-11-12 13:24:03Z antu123 $
# Description: Gather installed packages/rpms/etc for local security checks
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
# Tim Brown <timb@openvas.org>
#
# Updated by : Antu Sanadi <santu@secpod.com>  2010-11-15
#  - Updated to check for Ubuntu 10.10
#  - Updated to check for openSUSE 11.3
#  - Updated to check for Ubuntu 11.04
#  - Updated to check for Fedora 15 on 2011-07-11
#  - Updated to check for Fedora 16 on 2012-03-21
#  - Updated to check for Ubuntu 12.04 on 2012-05-04
#  - Updated to check for Mandriva 2011.0 on 2012-05-07
#  - Updated to check for Ubuntu 12.10 on 2012-10-31
#  - Updated to check for openSUSE 12.1 on 2012-12-13
#  - Updated to check for openSUSE 12.1 on 2013-03-08
#  - Updated to check for Ubuntu 13.10 on 2013-11-11
#
# Updated by : Sooraj KS <kssooraj@secpod.com>  2012-01-25
#  - Added Null check for oskey in function register_detected_os
#  - Updated to check for Ubuntu 11.10 on 2012-03-19
#  - Added CPE for RedHat 6
#
# Updated by : Rachana Shetty <srachana@secpod.com> 2012-09-27
#  - Removed '{SIGGPG:pgpsig}' option from the rpm command
#    for Redhat Enterprise releases 2,3,4,5,6
#
# Updated by : Thanga Prakash S <tprakash@secpod.com> 2013-08-21
#  - Updated to check for Fedora 19
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Copyright (c) 2008 Tim Brown
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

include("revisions-lib.inc");
tag_summary = "This script will, if given a userid/password or
key to the remote system, login to that system,
determine the OS it is running, and for supported
systems, extract the list of installed packages/rpms.";

if(description)
{
 script_id(50282);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 61 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-12 14:24:03 +0100 (Di, 12. Nov 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:05:49 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("Determine OS and list of installed packages via SSH login");

 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);

 script_summary("Determine OS and list of installed packages via SSH login");
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com & Tim Brown");
 script_family("General");
 script_dependencies("find_service.nasl", "ssh_authorization.nasl");
 script_mandatory_keys("login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
cmdline = 0;
include("ssh_func.inc");
include("host_details.inc");
include("cpe.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.50282";
SCRIPT_DESC = "Determine OS and list of installed packages via SSH login";

OS_CPE = make_array(
    # Redhat Linux
    "RH7.3",  "cpe:/o:redhat:linux:7.3",
    "RH8.0",  "cpe:/o:redhat:linux:8.0",
    "RH9",    "cpe:/o:redhat:linux:9",

    # Fedora
    "FC1",  "cpe:/o:fedoraproject:fedora_core:1",
    "FC2",  "cpe:/o:fedoraproject:fedora_core:2",
    "FC3",  "cpe:/o:fedoraproject:fedora_core:3",
    "FC4",  "cpe:/o:fedoraproject:fedora_core:4",
    "FC5",  "cpe:/o:fedoraproject:fedora_core:5",
    "FC6",  "cpe:/o:fedoraproject:fedora_core:6",
    "FC7",  "cpe:/o:fedoraproject:fedora:7",
    "FC8",  "cpe:/o:fedoraproject:fedora:8",
    "FC9",  "cpe:/o:fedoraproject:fedora:9",
    "FC10", "cpe:/o:fedoraproject:fedora:10",
    "FC11", "cpe:/o:fedoraproject:fedora:11",
    "FC12", "cpe:/o:fedoraproject:fedora:12",
    "FC13", "cpe:/o:fedoraproject:fedora:13",
    "FC14", "cpe:/o:fedoraproject:fedora:14",
    "FC15", "cpe:/o:fedoraproject:fedora:15",
    "FC16", "cpe:/o:fedoraproject:fedora:16",
    "FC17", "cpe:/o:fedoraproject:fedora:17",
    "FC18", "cpe:/o:fedoraproject:fedora:18",
    "FC19", "cpe:/o:fedoraproject:fedora:19",

    # RHEL
    "RHENT_2.1",  "cpe:/o:redhat:enterprise_linux:2.1",
    "RHENT_3",    "cpe:/o:redhat:enterprise_linux:3",
    "RHENT_4",    "cpe:/o:redhat:enterprise_linux:4",
    "RHENT_5",    "cpe:/o:redhat:enterprise_linux:5",
    "RHENT_6",    "cpe:/o:redhat:enterprise_linux:6",

    # Mandriva/Mandrake
    "MNDK_7.2",     "cpe:/o:mandrakesoft:mandrake_linux:7.2",
    "MNDK_8.0",     "cpe:/o:mandrakesoft:mandrake_linux:8.0",
    "MNDK_8.1",     "cpe:/o:mandrakesoft:mandrake_linux:8.1",
    "MNDK_9.1",     "cpe:/o:mandrakesoft:mandrake_linux:9.1",
    "MNDK_9.2",     "cpe:/o:mandrakesoft:mandrake_linux:9.2",
    "MNDK_10.0",    "cpe:/o:mandrakesoft:mandrake_linux:10.0",
    "MNDK_10.1",    "cpe:/o:mandrakesoft:mandrake_linux:10.1",
    "MNDK_10.2",    "cpe:/o:mandrakesoft:mandrake_linux:10.2",
    "MNDK_2006.0",  "cpe:/o:mandriva:linux:2006.0",
    "MNDK_2007.0",  "cpe:/o:mandriva:linux:2007.0",
    "MNDK_2007.1",  "cpe:/o:mandriva:linux:2007.1",
    "MNDK_2008.0",  "cpe:/o:mandriva:linux:2008.0",
    "MNDK_2008.1",  "cpe:/o:mandriva:linux:2008.1",
    "MNDK_2009.1",  "cpe:/o:mandriva:linux:2009.0",
    "MNDK_2009.0",  "cpe:/o:mandriva:linux:2009.1",
    "MNDK_2010.0",  "cpe:/o:mandriva:linux:2010.0",
    "MNDK_2010.1",  "cpe:/o:mandriva:linux:2010.1",
    "MNDK_2011.0",  "cpe:/o:mandriva:linux:2011.0",
    "MNDK_mes5",    "cpe:/o:mandriva:enterprise_server:5",
    "MNDK_mes5.2",  "cpe:/o:mandriva:enterprise_server:5",

    # CentOS
    "CentOS2", "cpe:/o:centos:centos:2",
    "CentOS3", "cpe:/o:centos:centos:3",
    "CentOS4", "cpe:/o:centos:centos:4",
    "CentOS5", "cpe:/o:centos:centos:5",
    "CentOS6", "cpe:/o:centos:centos:6",

    # Ubuntu
    "UBUNTU4.1",      "cpe:/o:canonical:ubuntu_linux:4.10",
    "UBUNTU5.04",     "cpe:/o:canonical:ubuntu_linux:5.04",
    "UBUNTU5.10",     "cpe:/o:canonical:ubuntu_linux:5.10",
    "UBUNTU6.06 LTS", "cpe:/o:canonical:ubuntu_linux:6.06:-:lts",
    "UBUNTU6.10",     "cpe:/o:canonical:ubuntu_linux:6.10",
    "UBUNTU7.04",     "cpe:/o:canonical:ubuntu_linux:7.04",
    "UBUNTU7.10",     "cpe:/o:canonical:ubuntu_linux:7.10",
    "UBUNTU8.04 LTS", "cpe:/o:canonical:ubuntu_linux:8.04:-:lts",
    "UBUNTU8.10",     "cpe:/o:canonical:ubuntu_linux:8.10",
    "UBUNTU9.04",     "cpe:/o:canonical:ubuntu_linux:9.04",
    "UBUNTU9.10",     "cpe:/o:canonical:ubuntu_linux:9.10",
    "UBUNTU10.04 LTS","cpe:/o:canonical:ubuntu_linux:10.04:-:lts",
    "UBUNTU10.10",    "cpe:/o:canonical:ubuntu_linux:10.10",
    "UBUNTU11.04",    "cpe:/o:canonical:ubuntu_linux:11.04",
    "UBUNTU11.10",    "cpe:/o:canonical:ubuntu_linux:11.10",
    "UBUNTU12.04 LTS","cpe:/o:canonical:ubuntu_linux:12.04",
    "UBUNTU12.10",    "cpe:/o:canonical:ubuntu_linux:12.10",
    "UBUNTU13.04",    "cpe:/o:canonical:ubuntu_linux:13.04",
    "UBUNTU13.10",    "cpe:/o:canonical:ubuntu_linux:13.10", 

    # Connectiva Linux
    "CL9",  "cpe:/a:connectiva:linux:9.0",
    "CL10", "cpe:/a:connectiva:linux:10.0",

    # Debian
    "DEB2.2", "cpe:/o:debian:debian_linux:2.2",
    "DEB3.0", "cpe:/o:debian:debian_linux:3.0",
    "DEB3.1", "cpe:/o:debian:debian_linux:3.1",
    "DEB4.0", "cpe:/o:debian:debian_linux:4.0",
    "DEB5.0", "cpe:/o:debian:debian_linux:5.0",
    "DEB6.0", "cpe:/o:debian:debian_linux:6.0",
    "DEB7.0", "cpe:/o:debian:debian_linux:7.0",

    # Turbo Linux (XXX: no CPE available)
    #"TLS7",   "",
    #"TLWS7",  "",
    #"TLS8",   "",
    #"TLWS8",  "",
    #"TLDT10", "",
    #"TLS10",  "",

    # Slackware
    "SLK8.1",  "cpe:/o:slackware:slackware_linux:8.1",
    "SLK9.0",  "cpe:/o:slackware:slackware_linux:9.0",
    "SLK9.1",  "cpe:/o:slackware:slackware_linux:9.1",
    "SLK10.0", "cpe:/o:slackware:slackware_linux:10.0",
    "SLK10.1", "cpe:/o:slackware:slackware_linux:10.1",
    "SLK10.2", "cpe:/o:slackware:slackware_linux:10.2",
    "SLK11.0", "cpe:/o:slackware:slackware_linux:11.0",
    "SLK12.0", "cpe:/o:slackware:slackware_linux:12.0",
    "SLK12.1", "cpe:/o:slackware:slackware_linux:12.1",
    "SLK12.2", "cpe:/o:slackware:slackware_linux:12.2",
    "SLK13.0", "cpe:/o:slackware:slackware_linux:13.0",
    "SLK13.1", "cpe:/o:slackware:slackware_linux:13.1",
    "SLK13.37", "cpe:/o:slackware:slackware_linux:13.37",
    "SLK14.0", "cpe:/o:slackware:slackware_linux:14.0",

    # SuSE
    "SLES9.0",  "cpe:/o:suse:linux_enterprise_server:9",
    "SLES10.0", "cpe:/o:suse:linux_enterprise_server:10",
    "SLES11.0", "cpe:/o:suse:linux_enterprise_server:11",

    "openSUSE10.2", "cpe:/o:novell:opensuse:10.2",
    "openSUSE10.3", "cpe:/o:novell:opensuse:10.3",
    "openSUSE11.0", "cpe:/o:novell:opensuse:11.0",
    "openSUSE11.1", "cpe:/o:novell:opensuse:11.1",
    "openSUSE11.2", "cpe:/o:novell:opensuse:11.2",
    "openSUSE11.3", "cpe:/o:novell:opensuse:11.3",
    "openSUSE11.4", "cpe:/o:novell:opensuse:11.4",
    "openSUSE12.1", "cpe:/o:novell:opensuse:12.1",
    "openSUSE12.2", "cpe:/o:novell:opensuse:12.2",

    "SUSE7.3",  "cpe:/o:novell:suse_linux:7.3",
    "SUSE8.0",  "cpe:/o:novell:suse_linux:8.0",
    "SUSE8.1",  "cpe:/o:novell:suse_linux:8.1",
    "SUSE8.2",  "cpe:/o:novell:suse_linux:8.2",
    "SUSE9.0",  "cpe:/o:novell:suse_linux:9.0",
    "SUSE9.1",  "cpe:/o:novell:suse_linux:9.1",
    "SUSE9.2",  "cpe:/o:novell:suse_linux:9.2",
    "SUSE9.3",  "cpe:/o:novell:suse_linux:9.3",
    "SUSE10.1", "cpe:/o:novell:suse_linux:10.1",
    "SUSE10.2", "cpe:/o:novell:suse_linux:10.2",
    "SUSE10.3", "cpe:/o:novell:suse_linux:10.3",
    "SUSE11",   "cpe:/o:novell:suse_linux:11.0",

    # Trustix
    "TSL1.1",   "cpe:/o:trustix:secure_linux:1.1",
    "TSL1.2",   "cpe:/o:trustix:secure_linux:1.2",
    "TSL1.5",   "cpe:/o:trustix:secure_linux:1.5",
    "TSL2.0",   "cpe:/o:trustix:secure_linux:2.0",
    "TSL2.1",   "cpe:/o:trustix:secure_linux:2.1",
    "TSL2.2",   "cpe:/o:trustix:secure_linux:2.2",
    "TSL3.0",   "cpe:/o:trustix:secure_linux:3.0",
    "TSL3.0.5", "cpe:/o:trustix:secure_linux:3.0.5",

    # Gentoo
    "GENTOO", "cpe:/o:gentoo:linux",

    # HP-UX
    "HPUX10.01", "cpe:/o:hp:hp-ux:10.01",
    "HPUX10.10", "cpe:/o:hp:hp-ux:10.10",
    "HPUX10.20", "cpe:/o:hp:hp-ux:10.20",
    "HPUX10.24", "cpe:/o:hp:hp-ux:10.24",
    "HPUX10.26", "cpe:/o:hp:hp-ux:10.26",
    "HPUX11.00", "cpe:/o:hp:hp-ux:11.00",
    "HPUX11.04", "cpe:/o:hp:hp-ux:11.04",
    "HPUX11.11", "cpe:/o:hp:hp-ux:11.11",
    "HPUX11.20", "cpe:/o:hp:hp-ux:11.20",
    "HPUX11.22", "cpe:/o:hp:hp-ux:11.22",
    "HPUX11.23", "cpe:/o:hp:hp-ux:11.23",
    "HPUX11.31", "cpe:/o:hp:hp-ux:11.31",
    "HPUX11.23", "cpe:/o:hp:hp-ux:11.23"
);


port = get_preference("auth_port_ssh");
if(!port) {
    port = get_kb_item("Services/ssh");
}
if(!port) {
    port = 22;
}
sock = ssh_login_or_reuse_connection();
if(!sock) {
    exit(0);
}

# First command: Grab uname -a of the remote system
uname = ssh_cmd(socket:sock, cmd:"uname -a");
if(isnull(uname))exit(0);

set_kb_item(name: "ssh/login/uname", value:uname);

# GNU/Linux platforms:


function register_detected_os(os, oskey) {
    if(!isnull(oskey))
        set_kb_item(name:"ssh/login/release", value:oskey);

    register_host_detail(name:"OS", value:os, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    if (!isnull(oskey) && !isnull(OS_CPE[oskey]))
        register_host_detail(name:"OS", value:OS_CPE[oskey], nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}


# Ok...let's first check if this is a RedHat/Fedora Core/Mandrake release
rls = ssh_cmd(socket:sock, cmd:"cat /etc/redhat-release");
if("Red Hat Linux release 7.3" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"RH7.3");
    exit(0);
}
if("Red Hat Linux release 8.0 (Psyche)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"RH8.0");
    exit(0);
}
if("Red Hat Linux release 9 (Shrike)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"RH9");
    exit(0);
}
if("Fedora Core release 1 (Yarrow)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC1");
    exit(0);
}
if("Fedora Core release 2 (Tettnang)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC2");
    exit(0);
}
if("Fedora Core release 3 (Heidelberg)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC3");
    exit(0);
}
if("Fedora Core release 4 (Stentz)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC4");
    exit(0);
}
if("Fedora Core release 5 (Bordeaux)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC5");
    exit(0);
}
if("Fedora Core release 6 (Zod)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC6");
    exit(0);
}
if("Fedora release 7 (Moonshine)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC7");
    exit(0);
}
if("Fedora release 8 (Werewolf)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC8");
    exit(0);
}
if("Fedora release 9 (Sulphur)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC9");
    exit(0);
}
if("Fedora release 10 (Cambridge)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC10");
    exit(0);
}
if("Fedora release 11 (Leonidas)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC11");
    exit(0);
}
if("Fedora release 12 (Constantine)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC12");
    exit(0);
}
if("Fedora release 13 (Goddard)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC13");
    exit(0);
}

if("Fedora release 14 (Laughlin)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC14");
    exit(0);
}

if("Fedora release 15 (Lovelock)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC15");
    exit(0);
}

if("Fedora release 16 (Verne)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC16");
    exit(0);
}

if("Fedora release 17 (Beefy Miracle)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC17");
    exit(0);
}

if("Fedora release 18 (Spherical Cow)" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC18");
    exit(0);
}

if("Fedora release 19" >< rls && "Cat" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"FC19");
    exit(0);
}


# Red Hat Enterprise Linux ES release 2.1 (Panama)
# Red Hat Enterprise Linux AS release 3 (Taroon Update 1)
# Red Hat Enterprise Linux AS release 3 (Taroon Update 2)
# Red Hat Enterprise Linux AS release 3 (Taroon Update 3)
# Red Hat Enterprise Linux Desktop release 3.90

if(egrep(pattern:"Red Hat Enterprise.*release 2\.1", string:rls)) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"RHENT_2.1");
    exit(0);
}
if(egrep(pattern:"Red Hat Enterprise.*release 3[ .]", string:rls)) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"RHENT_3");
    exit(0);
}
if(egrep(pattern:"Red Hat Enterprise.*release 4[ .]", string:rls)) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"RHENT_4");
    exit(0);
}
if(egrep(pattern:"Red Hat Enterprise.*release 5[ .]", string:rls)) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"RHENT_5");
    exit(0);
}
if(egrep(pattern:"Red Hat Enterprise.*release 6[ .]", string:rls)) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"RHENT_6");
    exit(0);
}

if("Mandriva Linux Enterprise Server release 5.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_mes5");
    exit(0);
}

if("Mandriva Linux Enterprise Server release 5.2" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_mes5.2");
    exit(0);
}

if("Mandriva Linux release 2011.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2011.0");
    exit(0);
}

if("Mandriva Linux release 2010.1" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2010.1");
    exit(0);
}

if("Mandriva Linux release 2010.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2010.0");
    exit(0);
}
if("Mandriva Linux release 2009.1" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2009.1");
    exit(0);
}
if("Mandriva Linux release 2009.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2009.0");
    exit(0);
}
if("Mandriva Linux release 2008.1" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2008.1");
    exit(0);
}
if("Mandriva Linux release 2008.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2008.0");
    exit(0);
}
if("Mandriva Linux release 2007.1" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2007.1");
    exit(0);
}
if("Mandriva Linux release 2007.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2007.0");
    exit(0);
}
if("Mandriva Linux release 2006.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_2006.0");
    exit(0);
}
if("Mandrakelinux release 10.2" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_10.2");
    exit(0);
}
if("Mandrakelinux release 10.1" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_10.1");
    exit(0);
}
if("Mandrake Linux release 10.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_10.0");
    exit(0);
}
if("Mandrake Linux release 9.2" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_9.2");
    exit(0);
}
if("Mandrake Linux release 9.1" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_9.1");
    exit(0);
}
if("Mandrake Linux release 8.1" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_8.1");
    exit(0);
}
if("Mandrake Linux release 8.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_8.0");
    exit(0);
}
if("Mandrake Linux release 7.2" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"MNDK_7.2");
    exit(0);
}

# Ok...also using /etc/redhat-release is CentOS...let's try them now
# We'll stay with major release # checking unless we find out we need to do
# otherwise.
#CentOS release 4.0 (Final)
#CentOS release 4.1 (Final)
#CentOS release 3.4 (final)

if("CentOS release 6" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running CentOS release 6"));
    register_detected_os(os:"CentOS release 6", oskey:"CentOS6");
    exit(0);
}


if("CentOS release 5" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running CentOS release 5"));
    register_detected_os(os:"CentOS release 5", oskey:"CentOS5");
    exit(0);
}

if("CentOS release 4" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running CentOS release 4"));
    register_detected_os(os:"CentOS release 4", oskey:"CentOS4");
    exit(0);
}
if("CentOS release 3" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running CentOS release 3"));
    register_detected_os(os:"CentOS release 3", oskey:"CentOS3");
    exit(0);
}
if("CentOS release 2" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running CentOS release 2"));
    register_detected_os(os:"CentOS release 2", oskey:"CentOS2");
    exit(0);
}

# Hmmm...is it Ubuntu?
rls = ssh_cmd(socket:sock, cmd:"cat /etc/lsb-release");
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=4.10"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 4.10"));
    register_detected_os(os:"Ubuntu 4.10", oskey:"UBUNTU4.1");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=5.04"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 5.04"));
    register_detected_os(os:"Ubuntu 5.04", oskey:"UBUNTU5.04");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=5.10"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 5.10"));
    register_detected_os(os:"Ubuntu 5.10", oskey:"UBUNTU5.10");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=6.06"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 6.06"));
    register_detected_os(os:"Ubuntu 6.06", oskey:"UBUNTU6.06 LTS");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=6.10"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 6.10"));
    register_detected_os(os:"Ubuntu 6.10", oskey:"UBUNTU6.10");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=7.04"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 7.04"));
    register_detected_os(os:"Ubuntu 7.04", oskey:"UBUNTU7.04");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=7.10"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 7.10"));
    register_detected_os(os:"Ubuntu 7.10", oskey:"UBUNTU7.10");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=8.04"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 8.04 LTS"));
    register_detected_os(os:"Ubuntu 8.04 LTS", oskey:"UBUNTU8.04 LTS");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=8.10"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 8.10"));
    register_detected_os(os:"Ubuntu 8.10", oskey:"UBUNTU8.10");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=9.04"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 9.04"));
    register_detected_os(os:"Ubuntu 9.04", oskey:"UBUNTU9.04");
    exit(0);
}
if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=9.10"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 9.10"));
    register_detected_os(os:"Ubuntu 9.10", oskey:"UBUNTU9.10");
    exit(0);
}

if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=10.04"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 10.04 LTS"));
    register_detected_os(os:"Ubuntu 10.04 LTS", oskey:"UBUNTU10.04 LTS");
    exit(0);
}

if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=10.10"><rls)
{
  buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
  if(!isnull(buf))
  {
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 10.10"));
    register_detected_os(os:"Ubuntu 10.10", oskey:"UBUNTU10.10");
    exit(0);
  }
}

if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=11.04"><rls)
{
  buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
  if(!isnull(buf))
  {
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 11.04"));
    register_detected_os(os:"Ubuntu 11.04", oskey:"UBUNTU11.04");
    exit(0);
  }
}

if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=11.10"><rls)
{
  buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
  if(!isnull(buf))
  {
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 11.10"));
    register_detected_os(os:"Ubuntu 11.10", oskey:"UBUNTU11.10");
    exit(0);
  }
}

if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=12.04"><rls) {
  buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
  if(!isnull(buf))
  {
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 12.04 LTS"));
    register_detected_os(os:"Ubuntu 12.04 LTS", oskey:"UBUNTU12.04 LTS");
    exit(0);
  }
}

if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=12.10"><rls) {
  buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
  if(!isnull(buf))
  {
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 12.10"));
    register_detected_os(os:"Ubuntu 12.10", oskey:"UBUNTU12.10");
    exit(0);
  }
}

if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=13.04"><rls) {
  buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
  if(!isnull(buf))
  {
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 13.04"));
    register_detected_os(os:"Ubuntu 13.04", oskey:"UBUNTU13.04");
    exit(0);
  }
}

if("DISTRIB_ID=Ubuntu"><rls && "DISTRIB_RELEASE=13.10"><rls) {
  buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
  if(!isnull(buf))
  {
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Ubuntu 13.10"));
    register_detected_os(os:"Ubuntu 13.10", oskey:"UBUNTU13.10");
    exit(0);
  }
}

# How about Conectiva Linux?
rls = ssh_cmd(socket:sock, cmd:"cat /etc/conectiva-release");
if("Conectiva Linux 9" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Conectiva Linux 9"));
    register_detected_os(os:"Conectiva Linux 9", oskey:"CL9");
    exit(0);
}
if("Conectiva Linux 10" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Conectiva Linux 10"));
    register_detected_os(os:"Conectiva Linux 10", oskey:"CL10");
    exit(0);
}

# How about Turbolinux?
# Turbolinux signatures:
# release 6.0 WorkStation (Shiga)       -- Unsupported
# TurboLinux release 6.1 Server (Naha)	-- Unsupported
# Turbolinux Server 6.5 (Jupiter)       -- Unsupported
# Turbolinux Server 7.0 (Esprit)
# Turbolinux Workstation 7.0 (Monza)
# Turbolinux Server 8.0 (Viper)
# Turbolinux Workstation 8.0 (SilverStone)
# Turbolinux Server 10.0 (Celica)
# Turbolinux Desktop 10.0 (Suzuka)
# -- Need:
#- Turbolinux Appliance Server 1.0 Hosting Edition
#- Turbolinux Appliance Server 1.0 Workgroup Edition
#- Turbolinux Home
#- Turbolinux 10 F...

rls = ssh_cmd(socket:sock, cmd:"cat /etc/turbolinux-release");
if("Turbolinux Server 7.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"TLS7");
    exit(0);
}
if("Turbolinux Workstation 7.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"TLWS7");
    exit(0);
}
if("Turbolinux Server 8.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"TLS8");
    exit(0);
}
if("Turbolinux Workstation 8.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"TLWS8");
    exit(0);
}
if("Turbolinux Desktop 10.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"TLDT10");
    exit(0);
}
if("Turbolinux Server 10.0" >< rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running ", rls));
    register_detected_os(os:rls, oskey:"TLS10");
    exit(0);
}
if("Turbolinux">< rls) {
    log_message(port:port, data:string("We have detected you are running a version of Turbolinux currently not supported by SecuritySpace.  Please report the following banner to SecuritySpace: ", rls));
    exit(0);
}

# Check for Univention Corporate Server (UCS)
rls = ssh_cmd(socket:sock, cmd:"cat /etc/issue");
if("Univention DC Master 2.2"><rls) {
    log_message(port:port, data:string("We are able to login and detect that you are running Univention Corporate Server 2.2"));
    register_detected_os(os:"Univention Corporate Server 2.2", oskey:"UCS2.2");
    exit(0);
}
if("Univention DC Master 2.3"><rls) {
    log_message(port:port, data:string("We are able to login and detect that you are running Univention Corporate Server 2.3"));
    register_detected_os(os:"Univention Corporate Server 2.3", oskey:"UCS2.3");
    exit(0);
}
if("Univention DC Master 2.4"><rls) {
    log_message(port:port, data:string("We are able to login and detect that you are running Univention Corporate Server 2.4"));
    register_detected_os(os:"Univention Corporate Server 2.4", oskey:"UCS2.4");
    exit(0);
}

# Hmmm...is it Debian?
rls = ssh_cmd(socket:sock, cmd:"cat /etc/debian_version");
if("2.2"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Debian 2.2 (Potato)"));
    register_detected_os(os:"Debian 2.2 (Potato)", oskey:"DEB2.2");
    exit(0);
}
if("3.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Debian 3.0 (Woody)"));
    register_detected_os(os:"Debian 3.0 (Woody)", oskey:"DEB3.0");
    exit(0);
}
if("3.1"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Debian 3.1 (Sarge)"));
    register_detected_os(os:"Debian 3.1 (Sarge)", oskey:"DEB3.1");
    exit(0);
}
if("4.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Debian 4.0 (Etch)"));
    register_detected_os(os:"Debian 4.0 (Etch)", oskey:"DEB4.0");
    exit(0);
}
if("5.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Debian 5.0 (Lenny)"));
    register_detected_os(os:"Debian 5.0 (Lenny)", oskey:"DEB5.0");
    exit(0);
}
if("6.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Debian 6.0 (Squeeze)"));
    register_detected_os(os:"Debian 6.0 (Squeeze)", oskey:"DEB6.0");
    exit(0);
}
if("7.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"COLUMNS=200 dpkg -l");
    set_kb_item(name: "ssh/login/packages", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Debian 7.0 (Wheezy)"));
    register_detected_os(os:"Debian 7.0 (Wheezy)", oskey:"DEB7.0");
    exit(0);
}


# How about Slackware?
rls = ssh_cmd(socket:sock, cmd:"cat /etc/slackware-version");
if("Slackware 14.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 14.0"));
    register_detected_os(os:"Slackware 14.0", oskey:"SLK14.0");
    exit(0);
}
if("Slackware 13.37"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 13.37"));
    register_detected_os(os:"Slackware 13.37", oskey:"SLK13.37");
    exit(0);
}
if("Slackware 13.1"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 13.1"));
    register_detected_os(os:"Slackware 13.1", oskey:"SLK13.1");
    exit(0);
}
if("Slackware 13.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 13.0"));
    register_detected_os(os:"Slackware 13.0", oskey:"SLK13.0");
    exit(0);
}
if("Slackware 12.2"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 12.2"));
    register_detected_os(os:"Slackware 12.2", oskey:"SLK12.2");
    exit(0);
}
if("Slackware 12.1"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 12.1"));
    register_detected_os(os:"Slackware 12.1", oskey:"SLK12.1");
    exit(0);
}
if("Slackware 12.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 12.0"));
    register_detected_os(os:"Slackware 12.0", oskey:"SLK12.0");
    exit(0);
}
if("Slackware 11.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 11.0"));
    register_detected_os(os:"Slackware 11.0", oskey:"SLK11.0");
    exit(0);
}
if("Slackware 10.2"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 10.2"));
    register_detected_os(os:"Slackware 10.2", oskey:"SLK10.2");
    exit(0);
}
if("Slackware 10.1"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 10.1"));
    register_detected_os(os:"Slackware 10.1", oskey:"SLK10.1");
    exit(0);
}
if("Slackware 10.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 10.0"));
    register_detected_os(os:"Slackware 10.0", oskey:"SLK10.0");
    exit(0);
}
if("Slackware 9.1"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 9.1"));
    register_detected_os(os:"Slackware 9.1", oskey:"SLK9.1");
    exit(0);
}
if("Slackware 9.0"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 9.0"));
    register_detected_os(os:"Slackware 9.0", oskey:"SLK9.0");
    exit(0);
}
if("Slackware 8.1"><rls) {
    buf = ssh_cmd(socket:sock, cmd:"ls /var/log/packages");
    set_kb_item(name: "ssh/login/slackpack", value:buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Slackware 8.1"));
    register_detected_os(os:"Slackware 8.1", oskey:"SLK8.1");
    exit(0);
}

# How about SuSe? and openSUSE?

rls = ssh_cmd(socket:sock, cmd:"cat /etc/SuSE-release");
if("SUSE Linux Enterprise Server 11 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux Enterprise Server 11"));
    register_detected_os(os:"SuSE Linux Enterprise Server 11", oskey:"SLES11.0");
    exit(0);
}
if("SUSE Linux Enterprise Server 10 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux Enterprise Server 10"));
    register_detected_os(os:"SuSE Linux Enterprise Server 10", oskey:"SLES10.0");
    exit(0);
}
if("SUSE LINUX Enterprise Server 9 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux Enterprise Server 9"));
    register_detected_os(os:"SuSE Linux Enterprise Server 9", oskey:"SLES9.0");
    exit(0);
}

if("openSUSE 12.2 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 12.2"));
    register_detected_os(os:"openSUSE 12.2", oskey:"openSUSE12.2");
    exit(0);
}

if("openSUSE 12.1 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 12.1"));
    register_detected_os(os:"openSUSE 12.1", oskey:"openSUSE12.1");
    exit(0);
}

if("openSUSE 11.4 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 11.4"));
    register_detected_os(os:"openSUSE 11.4", oskey:"openSUSE11.4");
    exit(0);
}

if("openSUSE 11.3 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 11.3"));
    register_detected_os(os:"openSUSE 11.3", oskey:"openSUSE11.3");
    exit(0);
}
if("openSUSE 11.2 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 11.2"));
    register_detected_os(os:"openSUSE 11.2", oskey:"openSUSE11.2");
    exit(0);
}
if("openSUSE 11.1 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 11.1"));
    register_detected_os(os:"openSUSE 11.1", oskey:"openSUSE11.1");
    exit(0);
}
if("openSUSE 11.0 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 11.0"));
    register_detected_os(os:"openSUSE 11.0", oskey:"openSUSE11.0");
    exit(0);
}
if("openSUSE 10.3 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 10.3"));
    register_detected_os(os:"openSUSE 10.3", oskey:"openSUSE10.3");
    exit(0);
}

if("openSUSE 10.2 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 10.2"));
    register_detected_os(os:"openSUSE 10.2", oskey:"openSUSE10.2");
    exit(0);
}

if("openSUSE 10.1 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running openSUSE 10.1"));
    register_detected_os(os:"openSUSE 10.1", oskey:"openSUSE10.1");
    exit(0);
}

if("SUSE LINUX 11 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 11"));
    register_detected_os(os:"SuSE Linux 11", oskey:"SUSE11");
    exit(0);
}
if("SUSE LINUX 10.3 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 10.3"));
    register_detected_os(os:"SuSE Linux 10.3", oskey:"SUSE10.3");
    exit(0);
}
if("SUSE LINUX 10.2 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 10.2"));
    register_detected_os(os:"SuSE Linux 10.2", oskey:"SUSE10.2");
    exit(0);
}
if("SUSE LINUX 10.1 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 10.1"));
    register_detected_os(os:"SuSE Linux 10.1", oskey:"SUSE10.1");
    exit(0);
}
if("SuSE Linux 9.3 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 9.3"));
    register_detected_os(os:"SuSE Linux 9.3", oskey:"SUSE9.3");
    exit(0);
}
if("SuSE Linux 9.2 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 9.2"));
    register_detected_os(os:"SuSE Linux 9.2", oskey:"SUSE9.2");
    exit(0);
}
if("SuSE Linux 9.1 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 9.1"));
    register_detected_os(os:"SuSE Linux 9.1", oskey:"SUSE9.1");
    exit(0);
}
if("SuSE Linux 9.0 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 9.0"));
    register_detected_os(os:"SuSE Linux 9.0", oskey:"SUSE9.0");
    exit(0);
}
if("SuSE Linux 8.2 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 8.2"));
    register_detected_os(os:"SuSE Linux 8.2", oskey:"SUSE8.2");
    exit(0);
}
if("SuSE Linux 8.1 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 8.1"));
    register_detected_os(os:"SuSE Linux 8.1", oskey:"SUSE8.1");
    exit(0);
}
if("SuSE Linux 8.0 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 8.0"));
    register_detected_os(os:"SuSE Linux 8.0", oskey:"SUSE8.0");
    exit(0);
}
if("SuSE Linux 7.3 "><rls) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running SuSE Linux 7.3"));
    register_detected_os(os:"SuSE Linux 7.3", oskey:"SUSE7.3");
    exit(0);
}


# How about Trustix?
rls = ssh_cmd(socket:sock, cmd:"cat /etc/release");
rls2 = ssh_cmd(socket:sock, cmd:"cat /etc/trustix-release");
if("Trustix Secure Linux release 3.0.5"><rls ||
       "Trustix Secure Linux release 3.0.5"><rls2) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Trustix 3.0.5"));
    register_detected_os(os:"Trustix 3.0.5", oskey:"TSL3.0.5");
    exit(0);
}
if("Trustix Secure Linux release 3.0"><rls ||
       "Trustix Secure Linux release 3.0"><rls2) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Trustix 3.0"));
    register_detected_os(os:"Trustix 3.0", oskey:"TSL3.0");
    exit(0);
}
if("Trustix Secure Linux release 2.2"><rls ||
       "Trustix Secure Linux release 2.2"><rls2) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Trustix 2.2"));
    register_detected_os(os:"Trustix 2.2", oskey:"TSL2.2");
    exit(0);
}
if("Trustix Secure Linux release 2.1"><rls ||
       "Trustix Secure Linux release 2.1"><rls2) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Trustix 2.1"));
    register_detected_os(os:"Trustix 2.1", oskey:"TSL2.1");
    exit(0);
}
if("Trustix Secure Linux release 2.0"><rls ||
       "Trustix Secure Linux release 2.0"><rls2) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Trustix 2.0"));
    register_detected_os(os:"Trustix 2.0", oskey:"TSL2.0");
    exit(0);
}
if("Trustix Secure Linux release 1.5"><rls ||
       "Trustix Secure Linux release 1.5"><rls2) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Trustix 1.5"));
    register_detected_os(os:"Trustix 1.5", oskey:"TSL1.5");
    exit(0);
}
if("Trustix Secure Linux release 1.2"><rls ||
       "Trustix Secure Linux release 1.2"><rls2) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Trustix 1.2"));
    register_detected_os(os:"Trustix 1.2", oskey:"TSL1.2");
    exit(0);
}
if("Trustix Secure Linux release 1.1"><rls ||
       "Trustix Secure Linux release 1.1"><rls2) {
    buf = ssh_cmd(socket:sock, cmd:"/bin/rpm -qa --qf '%{NAME}~%{VERSION}~%{RELEASE};\n'");
    set_kb_item(name: "ssh/login/rpms", value: ";" + buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Trustix 1.1"));
    register_detected_os(os:"Trustix 1.1", oskey:"TSL1.1");
    exit(0);
}
# Missing Trustix e-2

# How about Gentoo? Note, just check that its ANY gentoo release, since the
# build # doesn't matter for purposes of checking package version numbers.
rls = ssh_cmd(socket:sock, cmd:"cat /etc/gentoo-release");
if("Gentoo"><rls) {
    set_kb_item(name: "ssh/login/gentoo", value: "GENTOO");
    buf = ssh_cmd(socket:sock, cmd:'find /var/db/pkg -mindepth 2 -maxdepth 2 -printf "%P\\n"');
    set_kb_item(name: "ssh/login/pkg", value: buf);
    # Determine the list of maintained packages
    buf = ssh_cmd(socket:sock, cmd: "find /usr/portage/ -wholename '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\([^/]*\)/.*/\([^/]*\)\.ebuild$,\1/\2,'");
    if(strlen(buf)==0) { # Earlier find used 'path' in place of 'wholename'
	buf = ssh_cmd(socket:sock, cmd: "find /usr/portage/ -path '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\([^/]*\)/.*/\([^/]*\)\.ebuild$,\1/\2,'");
    }
    set_kb_item(name: "ssh/login/gentoo_maintained", value: buf);
    log_message(port:port, data:string("We are able to login and detect that you are running Gentoo"));
    register_detected_os(os:"Gentoo", oskey:"GENTOO");
    exit(0);
}

# Non GNU/Linux platforms:


## HP-UX Operating System

if ("HP-UX" >< uname){
    rls = ssh_cmd(socket:sock, cmd:"uname -r");

    if("10.01"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 10.01"));
        register_detected_os(os:"HP-UX 10.01", oskey:"HPUX10.01");
	exit(0);
    }
    if("10.10"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 10.10"));
        register_detected_os(os:"HP-UX 10.10", oskey:"HPUX10.10");
	exit(0);
    }
    if("10.20"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 10.20"));
        register_detected_os(os:"HP-UX 10.20", oskey:"HPUX10.20");
	exit(0);
    }
    if("10.24"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 10.24"));
        register_detected_os(os:"HP-UX 10.24", oskey:"HPUX10.24");
	exit(0);
    }
    if("10.26"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 10.26"));
        register_detected_os(os:"HP-UX 10.26", oskey:"HPUX10.26");
	exit(0);
    }
    if("11.00"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 11.00"));
        register_detected_os(os:"HP-UX 11.00", oskey:"HPUX11.00");
	exit(0);
    }
    if("11.04"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 11.04"));
        register_detected_os(os:"HP-UX 11.04", oskey:"HPUX11.04");
	exit(0);
    }
    if("11.11"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 11.11"));
        register_detected_os(os:"HP-UX 11.11", oskey:"HPUX11.11");
	exit(0);
    }
    if("11.20"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 11.20"));
        register_detected_os(os:"HP-UX 11.20", oskey:"HPUX11.20");
	exit(0);
    }
    if("11.22"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 11.22"));
        register_detected_os(os:"HP-UX 11.22", oskey:"HPUX11.22");
	exit(0);
    }
    if("11.23"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 11.23"));
        register_detected_os(os:"HP-UX 11.23", oskey:"HPUX11.23");
	exit(0);
    }
    if("11.31"><rls) {
	buf = ssh_cmd(socket:sock, cmd:"swlist -l patch -a supersedes");
	set_kb_item(name: "ssh/login/hp_pkgsupersedes", value:buf);
	buf = ssh_cmd(socket:sock, cmd:"swlist -a revision -l fileset");
	set_kb_item(name: "ssh/login/hp_pkgrev", value:buf);
	log_message(port:port, data:string("We are able to login and detect that you are running HP-UX 11.31"));
        register_detected_os(os:"HP-UX 11.31", oskey:"HPUX11.31");
	exit(0);
    }
}

#How about FreeBSD?  If the uname line begins with "FreeBSD ", we have a match
if(substr(uname, 0, 7)=="FreeBSD ") {
    osversion = ssh_cmd(socket:sock, cmd:"uname -r");
    register_detected_os(os:osversion); 

    version=eregmatch(pattern:"^[^ ]+ [^ ]+ ([^ ]+)+",string:uname);
    splitup = eregmatch(pattern:"([^-]+)-([^-]+)-p([0-9]+)", string:version[1]);
    found = 0;
    if(!isnull(splitup)) {
	release = splitup[1];
	patchlevel = splitup[3];
	found = 1;
    } else {
	splitup = eregmatch(pattern:"([^-]+)-RELEASE", string:version[1]);
	if(!isnull(splitup)) {
	    release = splitup[1];
	    patchlevel = "0";
	    found = 1;
	} else {
	    splitup=eregmatch(pattern:"([^-]+)-SECURITY",string:version[1]);
	    if(!isnull(splitup)) {
		release = splitup[1];
		log_message(port:port, data:string("We have detected you are running FreeBSD ", splitup[0], ". It also appears that you are using freebsd-update, a binary update tool for keeping your distribution up to date.  We will not be able to check your core distribution for vulnerabilities, but we will check your installed ports packages."));
		found = 2;
	    } else {
		log_message(port:port, data:string("You appear to be running FreeBSD, but we do not recognize the output format of uname: ", uname, ". Local security checks will NOT be run."));
	    }
	}
    }
    if(found==1) {
	set_kb_item(name: "ssh/login/freebsdrel", value: release);
	set_kb_item(name: "ssh/login/freebsdpatchlevel", value: patchlevel);
	log_message(port:port, data:string("We are able to login and detect that you are running FreeBSD ", release, " Patch level: ", patchlevel));
    }
    if(found==2) {
	set_kb_item(name: "ssh/login/freebsdrel", value: release);
	log_message(port:port, data:string("We are able to login and detect that you are running FreeBSD ", release, " Patch level: Unknown"));
    }
    if(found!=0) {
	buf = ssh_cmd(socket:sock, cmd:"pkg_info");
	set_kb_item(name: "ssh/login/freebsdpkg", value:buf);
    }
    exit(0);
}

# Whilst we're at it, lets check if it's Solaris
if (substr(uname, 0, 5) == "SunOS ") {
    osversion = ssh_cmd(socket:sock, cmd:"uname -r");
    set_kb_item(name: "ssh/login/solosversion", value:osversion);
    hardwaretype = ssh_cmd(socket:sock, cmd:"uname -p");
    set_kb_item(name: "ssh/login/solhardwaretype", value:hardwaretype);
    buf = ssh_cmd(socket:sock, cmd:"pkginfo");
    set_kb_item(name: "ssh/login/solpackages", value:buf);
    buf = ssh_cmd(socket:sock, cmd:"showrev -p");
    set_kb_item(name: "ssh/login/solpatches", value:buf);
    if (hardwaretype >< "sparc") {
        register_detected_os(os:string("Solaris ", osversion, " Arch: SPARC"));
        log_message(port:port, data:string("We are able to login and detect that you are running Solaris ", osversion, " Arch: SPARC"));
    } else {
        register_detected_os(os:string("Solaris ", osversion, " Arch: x86"));
        log_message(port:port, data:string("We are able to login and detect that you are running Solaris ", osversion, " Arch: x86"));
    }

    solaris_cpe = build_cpe(value:osversion, pattern:"^([0-9.]+)", base:"cpe:/o:sun:solaris:");
    if (!isnull(solaris_cpe))
        register_host_detail(name:"OS", value:solaris_cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    exit(0);
}

#maybe it's a real OS... like Mac OS X :)
if ("Darwin" >< uname)
{
    buf = ssh_cmd(socket:sock, cmd:"sw_vers");
    register_detected_os(os:buf);
    log_message(data:string("We are able to login and detect that you are running:\n", buf, '\n'));
    buf = chomp(ssh_cmd(socket:sock, cmd:"sw_vers -productName"));
    set_kb_item(name: "ssh/login/osx_name", value:buf);
    buf = chomp(ssh_cmd(socket:sock, cmd:"sw_vers -productVersion"));
    set_kb_item(name: "ssh/login/osx_version", value:buf);
    buf = chomp(ssh_cmd(socket:sock, cmd:"sw_vers -buildVersion"));
    set_kb_item(name: "ssh/login/osx_build", value:buf);
    buf = ssh_cmd(socket:sock, cmd:"list=$(pkgutil --pkgs);for l in $list;do echo $l;v=$(pkgutil --pkg-info $l | grep version);echo ${v#version: };done;");
    set_kb_item(name: "ssh/login/osx_pkgs", value:buf);


    osx_cpe = build_cpe(value:buf, pattern:"Mac OS X (10\.[0-9]+\.[0-9]+)", base:"cpe:/o:apple:mac_os_x:");
    if (!isnull(osx_cpe))
        register_host_detail(name:"OS", value:osx_cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    exit(0);
}

#{ "NetBSD",     "????????????????",         },
#{ "OpenBSD",    "????????????????",         },
#{ "WhiteBox",   "????????????????",         },
#{ "Linspire",   "????????????????",         },
#{ "Desktop BSD","????????????????",         },
#{ "PC-BSD",     "????????????????",         },
#{ "FreeSBIE",   "????????????????",         },
#{ "JDS",        "/etc/sun-release",         },
#{ "Yellow Dog", "/etc/yellowdog-release",   },

log_message(port: 0, data: strcat('System identifier unknown: "', uname, '"\nTherefore no local security checks applied (missing list of installed packages) though ssh login provided and works'));
