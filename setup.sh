#!/bin/bash
set -x 
set -e

if [[ -f /tmp/provisioning_completed ]]; then
  exit 0
fi

date > /var/log/provisioning_began
# Setup a new ubuntu 12.10 server

export USERNAME=${1:-openflow} 
export APPNAME=${2:-openflow} 
export AUTHORIZED_KEYS=${3:-''}
export RUBY_VERSION=${4:-'1.9.3'}
export APT_PROXY=${5:-"http://192.168.1.65:3142"}
export DEBIAN_FRONTEND=noninteractive


# User a local apt-cache
function setup_apt_cache () {
  echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /tmp/01proxy
  sudo mv /tmp/01proxy /etc/apt/apt.conf.d/01proxy
  cp /etc/apt/sources.list /etc/apt/sources.list.orig
  # sed -i 's/http:\/\/.*\/ubuntu/http:\/\/192.168.1.65:3142/' /etc/apt/sources.list
}

function dist_upgrade () {
  echo "$FUNCNAME now executing..."
  sudo apt-get update
  sudo apt-get -y dist-upgrade
}

# install some tools I like to have
function install_common_tools () {
  echo "$FUNCNAME now executing..."
  sudo apt-get -y install nmap wget curl tree lsof vim  subversion mosh unzip patch git git-core links xfsprogs ngrep
}

# install some build and runtime needs
function build_tools () {
  echo "$FUNCNAME now executing."
  sudo apt-get -y install build-essential automake libtool bison autoconf libreadline-dev  openssl libreadline6 libreadline6-dev zlib1g zlib1g-dev libssl-dev libyaml-dev libsqlite3-dev sqlite3 libxml2-dev libxslt-dev libc6-dev ncurses-dev imagemagick libmagickcore-dev libmagick++-dev libpq-dev tcl
}

function install_java () {
  echo "\n Installing Java.."
  sudo apt-get -y install g++ openjdk-6-jre-headless ant openjdk-6-jdk  
  # comment above, and uncomment below to use the sun java7 binary install
  # sudo add-apt-repository ppa:webupd8team/java 
  # sudo apt-get install oracle-java7-installer
}

function instal_python () {
  sudo apt-get -y install python-pip
}

function setup_deploy_user () {
  echo "\n\n ---> $FUNCNAME now executing."
  sudo useradd -c 'The user used to deploy apps' -s '/bin/bash' -d /home/${USERNAME} -m ${USERNAME}
  sudo touch /etc/sudoers.d/91-${USERNAME}
  sudo chmod 0440 /etc/sudoers.d/91-${USERNAME}
  echo "echo \"${USERNAME} ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/91-${USERNAME}" | sudo bash
  sudo mkdir -p /home/${USERNAME}/.ssh
  echo "${AUTHORIZED_KEYS}" > /tmp/authorized_keys
  sudo mv /tmp/authorized_keys /home/${USERNAME}/.ssh/authorized_keys
  sudo chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}/.ssh
  # sudo -u ${USERNAME} 'ssh-keygen -b 4096 -t rsa -f /home/${USERNAME}/.ssh/id_rsa -P ""'
}

function setup_postgres () {
  echo "\n\n ---> $FUNCNAME now executing."
  sudo apt-get install -y postgresql-9.1 libpq-dev
  # createuser --echo  --superuser  deploy
  echo "CREATE USER ${USERNAME} WITH PASSWORD 'secret4${USERNAME}';
  ALTER USER ${USERNAME} WITH SUPERUSER;
  CREATE DATABASE ${APPNAME}_production">/tmp/pguser.psql
  sudo -u postgres sh -c "psql -f /tmp/pguser.psql"
  rm /tmp/pguser.psql
  sudo sh -c "echo 'localhost:5432:*:${USERNAME}:secret4${USERNAME}'>/home/${USERNAME}/.pgpass"
  sudo chown ${USERNAME}:${USERNAME} /home/${USERNAME}/.pgpass
  sudo chmod 0600 /home/${USERNAME}/.pgpass
}

function install_ruby () {
  echo "\n\n ---> $FUNCNAME now executing."
  sudo sh -c "echo 'gem: --no-ri --no-rdoc'>>/etc/gemrc"
  sudo apt-get -y install ruby1.9.1-full libnokogiri-ruby1.9.1
  sudo gem install bundler json foreman taps
}

function setup_www () {
  echo "\n\n  ---> $FUNCNAME now executing."
  sudo apt-get -y install nginx-full
  sudo mkdir -p /var/www/apps
  sudo chown -R ${USERNAME}:www-data /var/www
}

function setup_monitoring () {
  sudo apt-get install -y ganglia-monitor
  sudo apt-get install -y collectd libvirt0 collectd-dev
}

function setup_rvm () {
  echo "\n\n ---> $FUNCNAME now executing."
  sudo -i -u ${USERNAME} bash -c "curl -L https://raw.github.com/wayneeseguin/rvm/master/binscripts/rvm-installer | bash"
  sudo -i -u ${USERNAME} bash -c "echo \"gem: --no-rdoc --no-ri\" > ${WORKING_DIR}/.gemrc"
  sudo -i -u ${USERNAME} bash -c "echo \"source ${WORKING_DIR}/.rvm/scripts/rvm\">>${WORKING_DIR}/.bashrc"
  # source ${WORKING_DIR}/.rvm/scripts/rvm
  sudo -i -u ${USERNAME} bash -c "rvm install $RUBY_VERSION"
  sudo -i -u ${USERNAME} bash -c "rvm --default use $RUBY_VERSION"
  sudo -i -u ${USERNAME} bash -c "rvm rubygems current"
  sudo -i -u ${USERNAME} bash -c "gem install capistrano foreman pg pry awesome_print nokogiri oj multi_json faraday thin puma"
}

function setup_floodlight () {
  install_java #if not already installed
  sudo apt-get install build-essential default-jdk ant python-dev
  git clone git://github.com/floodlight/floodlight.git
  cd floodlight
  ant
  # java -jar floodlight.jar
}

function main () {
  setup_apt_cache
  
  # dist_upgrade
  setup_deploy_user
  install_common_tools
  build_tools
  
  # setup_postgres
  # setup_www
  # install_java
  # setup_monitoring
  # setup_rvm
  # setup_mininet
}






# ======================================================================================
# = CODE BELOW HERE IS MODIFIED VERSION OF THE install.sh SCRIPT FROM THE MININET REPO =
# ======================================================================================

#!/usr/bin/env bash

# Mininet install script for Ubuntu (and Debian Lenny)
# Brandon Heller (brandonh@stanford.edu)

# Fail on error
set -e

# Fail on unset var usage
set -o nounset

# Location of CONFIG_NET_NS-enabled kernel(s)
KERNEL_LOC=http://www.openflow.org/downloads/mininet

# Attempt to identify Linux release

DIST=Unknown
RELEASE=Unknown
CODENAME=Unknown

WORKING_DIR=/home/openflow
mkdir -p ${WORKING_DIR}

ARCH=`uname -m`
if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
if [ "$ARCH" = "i686" ]; then ARCH="i386"; fi

test -e /etc/debian_version && DIST="Debian"
grep Ubuntu /etc/lsb-release &> /dev/null && DIST="Ubuntu"
if [ "$DIST" = "Ubuntu" ] || [ "$DIST" = "Debian" ]; then
    install='sudo apt-get -y install'
    remove='sudo apt-get -y remove'
    pkginst='sudo dpkg -i'
    # Prereqs for this script
    if ! which lsb_release &> /dev/null; then
        $install lsb-release
    fi
    if ! which bc &> /dev/null; then
        $install bc
    fi
fi
if which lsb_release &> /dev/null; then
    DIST=`lsb_release -is`
    RELEASE=`lsb_release -rs`
    CODENAME=`lsb_release -cs`
fi
echo "Detected Linux distribution: $DIST $RELEASE $CODENAME $ARCH"

# Kernel params

if [ "$DIST" = "Ubuntu" ]; then
    if [ "$RELEASE" = "10.04" ]; then
        KERNEL_NAME='3.0.0-15-generic'
    else
        KERNEL_NAME=`uname -r`
    fi
    KERNEL_HEADERS=linux-headers-${KERNEL_NAME}
elif [ "$DIST" = "Debian" ] && [ "$ARCH" = "i386" ] && [ "$CODENAME" = "lenny" ]; then
    KERNEL_NAME=2.6.33.1-mininet
    KERNEL_HEADERS=linux-headers-${KERNEL_NAME}_${KERNEL_NAME}-10.00.Custom_i386.deb
    KERNEL_IMAGE=linux-image-${KERNEL_NAME}_${KERNEL_NAME}-10.00.Custom_i386.deb
else
    echo "Install.sh currently only supports Ubuntu and Debian Lenny i386."
    exit 1
fi

# More distribution info
DIST_LC=`echo $DIST | tr [A-Z] [a-z]` # as lower case

# Kernel Deb pkg to be removed:
KERNEL_IMAGE_OLD=linux-image-2.6.26-33-generic

DRIVERS_DIR=/lib/modules/${KERNEL_NAME}/kernel/drivers/net

OVS_RELEASE=1.4.0
OVS_PACKAGE_LOC=https://github.com/downloads/mininet/mininet
OVS_BUILDSUFFIX=-ignore # was -2
OVS_PACKAGE_NAME=ovs-$OVS_RELEASE-core-$DIST_LC-$RELEASE-$ARCH$OVS_BUILDSUFFIX.tar
#OVS_SRC=${WORKING_DIR}/openvswitch
OVS_TAG=v$OVS_RELEASE
OVS_BUILD=${WORKING_DIR}/openvswitch/build-$KERNEL_NAME
OVS_KMODS=($OVS_BUILD/datapath/linux/{openvswitch_mod.ko,brcompat_mod.ko})


# clone or pull a git repo, and change to the updated repo directory
function sync_git_repo () {
  REPO=$1
  NAME=$2
  if [[ -d ${WORKING_DIR}/$1 ]]; then
    cd ${WORKING_DIR}/$2 && git pull
  else
    git clone $1 ${WORKING_DIR}/$2
    cd ${WORKING_DIR}/$2
  fi 
}

function kernel {
    echo "Install Mininet-compatible kernel if necessary"
    sudo apt-get update
    if [ "$DIST" = "Ubuntu" ] &&  [ "$RELEASE" = "10.04" ]; then
        $install linux-image-$KERNEL_NAME
    elif [ "$DIST" = "Debian" ]; then
        # The easy approach: download pre-built linux-image and linux-headers packages:
        wget -c $KERNEL_LOC/$KERNEL_HEADERS
        wget -c $KERNEL_LOC/$KERNEL_IMAGE

        # Install custom linux headers and image:
        $pkginst $KERNEL_IMAGE $KERNEL_HEADERS

        # The next two steps are to work around a bug in newer versions of
        # kernel-package, which fails to add initrd images with the latest kernels.
        # See http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=525032
        # Generate initrd image if the .deb didn't install it:
        if ! test -e /boot/initrd.img-${KERNEL_NAME}; then
            sudo update-initramfs -c -k ${KERNEL_NAME}
        fi

        # Ensure /boot/grub/menu.lst boots with initrd image:
        sudo update-grub

        # The default should be the new kernel. Otherwise, you may need to modify
        # /boot/grub/menu.lst to set the default to the entry corresponding to the
        # kernel you just installed.
    fi
}

function kernel_clean {
    echo "Cleaning kernel..."

    # To save disk space, remove previous kernel
    if ! $remove $KERNEL_IMAGE_OLD; then
        echo $KERNEL_IMAGE_OLD not installed.
    fi

    # Also remove downloaded packages:
    rm -f ${WORKING_DIR}/linux-headers-* ${WORKING_DIR}/linux-image-*
}

# Install Mininet deps
function mn_deps {
    echo "Installing Mininet dependencies"
    $install gcc make screen psmisc xterm ssh iperf iproute \
        python-setuptools python-networkx cgroup-bin ethtool help2man \
        pyflakes pylint pep8

    if [ "$DIST" = "Ubuntu" ] && [ "$RELEASE" = "10.04" ]; then
        echo "Upgrading networkx to avoid deprecation warning"
        sudo easy_install --upgrade networkx
    fi

    # Add sysctl parameters as noted in the INSTALL file to increase kernel
    # limits to support larger setups:
    sudo su -c "cat ${WORKING_DIR}/mininet/util/sysctl_addon >> /etc/sysctl.conf"
    #TODO: changed to get around bug in HOME being root/ not /vagrant
    # sudo su -c "cat /home/vagrant/mininet/util/sysctl_addon >> /etc/sysctl.conf"

    # Load new sysctl settings:
    # sudo sysctl -p
    echo "Installing Mininet core"
    pushd ${WORKING_DIR}/mininet
    sudo make install
    popd
}

# The following will cause a full OF install, covering:
# -user switch
# The instructions below are an abbreviated version from
# http://www.openflowswitch.org/wk/index.php/Debian_Install
# ... modified to use Debian Lenny rather than unstable.
function of {
    echo "Installing OpenFlow reference implementation..."
    cd ${WORKING_DIR}/
    $install git-core autoconf automake autotools-dev pkg-config \
    make gcc libtool libc6-dev
    sync_git_repo git://openflowswitch.org/openflow.git openflow
    # Patch controller to handle more than 16 switches
    patch -p1 < ${WORKING_DIR}/mininet/util/openflow-patches/controller.patch

    # Resume the install:
    ./boot.sh
    ./configure
    make
    sudo make install

    # Remove avahi-daemon, which may cause unwanted discovery packets to be
    # sent during tests, near link status changes:
    $remove avahi-daemon

    # Disable IPv6.  Add to /etc/modprobe.d/blacklist:
    if [ "$DIST" = "Ubuntu" ]; then
        BLACKLIST=/etc/modprobe.d/blacklist.conf
    else
        BLACKLIST=/etc/modprobe.d/blacklist
    fi
    sudo sh -c "echo 'blacklist net-pf-10\nblacklist ipv6' >> $BLACKLIST"
    cd ${WORKING_DIR}
}

function wireshark {
    echo "Installing Wireshark dissector..."

    sudo apt-get install -y wireshark libgtk2.0-dev

    if [ "$DIST" = "Ubuntu" ] && [ "$RELEASE" != "10.04" ]; then
        # Install newer version
        sudo apt-get install -y scons mercurial libglib2.0-dev
        sudo apt-get install -y libwiretap-dev libwireshark-dev
        cd ${WORKING_DIR}/
        hg clone https://bitbucket.org/barnstorm/of-dissector
        cd of-dissector/src
        export WIRESHARK=/usr/include/wireshark
        scons
        # libwireshark0/ on 11.04; libwireshark1/ on later
        WSDIR=`ls -d /usr/lib/wireshark/libwireshark* | head -1`
        WSPLUGDIR=$WSDIR/plugins/
        sudo cp openflow.so $WSPLUGDIR
        echo "Copied openflow plugin to $WSPLUGDIR"
    else
        # Install older version from reference source
        cd ${WORKING_DIR}/openflow/utilities/wireshark_dissectors/openflow
        make
        sudo make install
    fi

    # Copy coloring rules: OF is white-on-blue:
    mkdir -p ${WORKING_DIR}/.wireshark
    cp ${WORKING_DIR}/mininet/util/colorfilters ${WORKING_DIR}/.wireshark
}


# Install Open vSwitch
# Instructions derived from OVS INSTALL, INSTALL.OpenFlow and README files.

function ovs {
    echo "Installing Open vSwitch..."

    # Required for module build/dkms install
    $install $KERNEL_HEADERS

    ovspresent=0

    # First see if we have packages
    # XXX wget -c seems to fail from github/amazon s3
    cd /tmp
    if wget $OVS_PACKAGE_LOC/$OVS_PACKAGE_NAME 2> /dev/null; then
        $install patch dkms fakeroot python-argparse
        tar xf $OVS_PACKAGE_NAME
        orig=`tar tf $OVS_PACKAGE_NAME`
        # Now install packages in reasonable dependency order
        order='dkms common pki openvswitch-switch brcompat controller'
        pkgs=""
        for p in $order; do
            pkg=`echo "$orig" | grep $p`
            # Annoyingly, things seem to be missing without this flag
            $pkginst --force-confmiss $pkg
        done
        ovspresent=1
    fi

    # Otherwise try distribution's OVS packages
    if [ "$DIST" = "Ubuntu" ] && [ `expr $RELEASE '>=' 11.10` = 1 ]; then
        if ! dpkg --get-selections | grep openvswitch-datapath; then
            # If you've already installed a datapath, assume you
            # know what you're doing and don't need dkms datapath.
            # Otherwise, install it.
            $install openvswitch-datapath-dkms
        fi
	if $install openvswitch-switch openvswitch-controller; then
            echo "Ignoring error installing openvswitch-controller"
        fi
        ovspresent=1
    fi

    # Switch can run on its own, but
    # Mininet should control the controller
    if [ -e /etc/init.d/openvswitch-controller ]; then
        if sudo service openvswitch-controller stop; then
            echo "Stopped running controller"
        fi
        sudo update-rc.d openvswitch-controller disable
    fi

    if [ $ovspresent = 1 ]; then
        echo "Done (hopefully) installing packages"
        cd ${WORKING_DIR}
        return
    fi

    # Otherwise attempt to install from source

    $install pkg-config gcc make python-dev libssl-dev libtool

    if [ "$DIST" = "Debian" ]; then
        if [ "$CODENAME" = "lenny" ]; then
            $install git-core
            # Install Autoconf 2.63+ backport from Debian Backports repo:
            # Instructions from http://backports.org/dokuwiki/doku.php?id=instructions
            sudo su -c "echo 'deb http://www.backports.org/debian lenny-backports main contrib non-free' >> /etc/apt/sources.list"
            sudo apt-get update
            sudo apt-get -y --force-yes install debian-backports-keyring
            sudo apt-get -y --force-yes -t lenny-backports install autoconf
        fi
    else
        $install git
    fi

    # Install OVS from release
    cd ${WORKING_DIR}/
    if [[ -d ${WORKING_DIR}/openvswitch ]]; then
      cd ${WORKING_DIR}/openvswitch && git pull
    else
       git clone git://openvswitch.org/openvswitch ${WORKING_DIR}/openvswitch
       cd ${WORKING_DIR}/openvswitch
    fi 
    git checkout $OVS_TAG
    ./boot.sh
    BUILDDIR=/lib/modules/${KERNEL_NAME}/build
    if [ ! -e $BUILDDIR ]; then
        echo "Creating build sdirectory $BUILDDIR"
        sudo mkdir -p $BUILDDIR
    fi
    opts="--with-linux=$BUILDDIR"
    mkdir -p $OVS_BUILD
    cd $OVS_BUILD
    ../configure $opts
    make
    sudo make install

    modprobe
}

function remove_ovs {
    pkgs=`dpkg --get-selections | grep openvswitch | awk '{ print $1;}'`
    echo "Removing existing Open vSwitch packages:"
    echo $pkgs
    if ! $remove $pkgs; then
        echo "Not all packages removed correctly"
    fi
    # For some reason this doesn't happen
    if scripts=`ls /etc/init.d/*openvswitch* 2>/dev/null`; then
        echo $scripts
        for s in $scripts; do
            s=$(basename $s)
            echo SCRIPT $s
            sudo service $s stop
            sudo rm -f /etc/init.d/$s
            sudo update-rc.d -f $s remove
        done
    fi
    echo "Done removing OVS"
}

# Install NOX with tutorial files
function nox {
    echo "Installing NOX w/tutorial files..."

    # Install NOX deps:
    $install autoconf automake g++ libtool python python-twisted \
		swig libssl-dev make
    if [ "$DIST" = "Debian" ]; then
        $install libboost1.35-dev
    elif [ "$DIST" = "Ubuntu" ]; then
        $install python-dev libboost-dev
        $install libboost-filesystem-dev
        $install libboost-test-dev
    fi
    # Install NOX optional deps:
    $install libsqlite3-dev python-simplejson

    # Fetch NOX destiny
    cd ${WORKING_DIR}
    sync_git_repo https://github.com/noxrepo/nox-classic.git noxcore
    if ! git checkout -b destiny remotes/origin/destiny ; then
        echo "Did not check out a new destiny branch - assuming current branch is destiny"
    fi

    # Apply patches
    git checkout -b tutorial-destiny
    git am ${WORKING_DIR}/mininet/util/nox-patches/*tutorial-port-nox-destiny*.patch
    if [ "$DIST" = "Ubuntu" ] && [ `expr $RELEASE '>=' 12.04` = 1 ]; then
        git am ${WORKING_DIR}/mininet/util/nox-patches/*nox-ubuntu12-hacks.patch
    fi

    # Build
    ./boot.sh
    mkdir build
    cd build
    ../configure
    make -j3
    #make check

    # Add NOX_CORE_DIR env var:
    sed -i -e 's|# for examples$|&\nexport NOX_CORE_DIR=${WORKING_DIR}/noxcore/build/src|' ${WORKING_DIR}/.bashrc

    # To verify this install:
    #cd ${WORKING_DIR}/noxcore/build/src
    #./nox_core -v -i ptcp:
}

# "Install POX, python openflow controlle (python NOX)r
function pox {
    echo "Installing POX into ${WORKING_DIR}/pox..."
    sync_git_repo https://github.com/noxrepo/pox.git pox
}

# Install OpenFlow Switch Test Framework
function oftest {
    echo "Installing oftest..."
    # Install deps:
    $install tcpdump python-scapy
    
    cd ${WORKING_DIR}/
    sync_git_repo git://github.com/floodlight/oftest oftest
    cd tools/munger
    sudo make install
}

# Install cbench
function cbench {
    echo "Installing cbench..."

    $install libsnmp-dev libpcap-dev libconfig-dev
    cd ${WORKING_DIR}/
    sync_git_repo git://openflow.org/oflops.git oflops
    sh boot.sh || true # possible error in autoreconf, so run twice
    sh boot.sh
    ./configure --with-openflow-src-dir=${WORKING_DIR}/openflow
    make
    sudo make install || true # make install fails; force past this
}

function other {
    echo "Doing other setup tasks..."

    # Enable command auto completion using sudo; modify ${WORKING_DIR}/.bashrc:
    # sed -i -e 's|# for examples$|&\ncomplete -cf sudo|' ~$USERNAME/.bashrc

    # Install tcpdump and tshark, cmd-line packet dump tools.  Also install gitk,
    # a graphical git history viewer.
    $install tcpdump tshark gitk

    # Install common text editors
    $install vim nano emacs

    # Install NTP
    $install ntp

    # Set git to colorize everything.
    git config --global color.diff auto
    git config --global color.status auto
    git config --global color.branch auto

    # Reduce boot screen opt-out delay. Modify timeout in /boot/grub/menu.lst to 1:
    if [ "$DIST" = "Debian" ]; then
        sudo sed -i -e 's/^timeout.*$/timeout         1/' /boot/grub/menu.lst
    fi

    # Clean unneeded debs:
    rm -f ${WORKING_DIR}/linux-headers-* ${WORKING_DIR}/linux-image-*
}

# Script to copy built OVS kernel module to where modprobe will
# find them automatically.  Removes the need to keep an environment variable
# for insmod usage, and works nicely with multiple kernel versions.
#
# The downside is that after each recompilation of OVS you'll need to
# re-run this script.  If you're using only one kernel version, then it may be
# a good idea to use a symbolic link in place of the copy below.
function modprobe {
    echo "Setting up modprobe for OVS kmod..."

    sudo cp $OVS_KMODS $DRIVERS_DIR
    sudo depmod -a ${KERNEL_NAME}
}




echo "Running all commands...as "
whoami
sudo printenv
printenv
setup_apt_cache
sudo apt-get update
dist_upgrade
setup_deploy_user
install_common_tools
# build_tools
install_java


# mininet setuo
sync_git_repo git://github.com/mininet/mininet.git mininet
cd ${WORKING_DIR}
kernel
mn_deps
of
wireshark
ovs
# NOX-classic is deprecated, but you can install it manually if desired.
# nox
pox
oftest
cbench
other
# test that it really works
sudo mn --test pingall
echo "Please reboot, then run ./mininet/util/install.sh -c to remove unneeded packages."
echo "Enjoy Mininet!"

date >> /tmp/provisioning_completed

exit 0

