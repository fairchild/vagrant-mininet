#!/bin/bash
# set -x 
set -e

date >> /tmp/provisioned
# Setup a new ubuntu 12.10 server

export USERNAME=${1:-openflow} 
export APPNAME=${2:-openflow} 
export AUTHORIZED_KEYS=${3:-'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8NtzlX2zc6YrjTM/28fozyaxxCoCWIoUb5VHE8bvqlDcrQVMfUIfJilhAL0mRwuMMgE+04h77CZ/NL8jJgFYixu7iRMcn67jGu8v5Gjluk0ZgsuS/P1tMxr3a5O1HWAJvWnF+r+kqMmca1TB6ELywPRbmN7xtRTPi0nwRj51xYo4rEGBJz2KfYRMS3Zf4WY6vhEov+rtcY2gOQaV5jcE7PUvUU2+ku3WzCJ6wRt1otYdCwAd7V97e7aIw2ku3hq0lpYikM6sboBlOGsZy7WjrlUDhhHNpe5Asi/pbMv0YGozwHdhKkOarno/BKr9okFwGBor6oSUiM66Fn+8d+yAJ fairchild@pickaxe'}
export RUBY_VERSION=${4:-'1.9.3'}
export APT_PROXY=${5:-"http://192.168.1.65:3142"}

export DEBIAN_FRONTEND=noninteractive

function dist_upgrade () {
  echo "$FUNCNAME now executing."
  echo "deb http://packages.dotdeb.org stable all
deb-src http://packages.dotdeb.org stable all" > /etc/apt/sources.list.d/dotdeb.org.list
  wget http://www.dotdeb.org/dotdeb.gpg
  sudo apt-key add dotdeb.gpg
  sudo apt-get -y update
  sudo apt-get -y dist-upgrade
}

function install_common_tools () {
  echo "$FUNCNAME now executing."
  # install some tools I like to have
  sudo apt-get -y install nmap wget curl tree lsof vim  subversion mosh unzip patch git git-core links xfsprogs
}

function build_tools () {
  echo "$FUNCNAME now executing."
  # install some build and runtime needs
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
  sudo sh -c "echo 'gem: --no-ri --no-rdoc'>/etc/gemrc"
  sudo apt-get -y install ruby1.9.1-full libnokogiri-ruby1.9.1
  sudo gem install bundler json foreman taps
}

function setup_www () {
  echo "\n\n  ---> $FUNCNAME now executing."
  sudo apt-get -y install nginx-full
  sudo mkdir -p /var/www/apps
  sudo chown -R ${USERNAME}:www-data /var/www
}

function setup_apt_cache () {
  echo "Acquire::http::Proxy \"${APT_PROXY}\";" > /tmp/01proxy
  sudo mv /tmp/01proxy /etc/apt/apt.conf.d/01proxy
}

function setup_monitoring () {
  sudo apt-get install -y  ganglia-monitor
  sudo apt-get install -y collectd libvirt0 collectd-dev
}

function setup_rvm () {
  echo "\n\n ---> $FUNCNAME now executing."
  sudo -i -u ${USERNAME} bash -c "curl -L https://raw.github.com/wayneeseguin/rvm/master/binscripts/rvm-installer | bash"
  sudo -i -u ${USERNAME} bash -c "echo \"gem: --no-rdoc --no-ri\" > ~/.gemrc"
  sudo -i -u ${USERNAME} bash -c "echo \"source ~/.rvm/scripts/rvm\">>~/.bashrc"
  # source ~/.rvm/scripts/rvm
  sudo -i -u ${USERNAME} bash -c "rvm install $RUBY_VERSION"
  sudo -i -u ${USERNAME} bash -c "rvm --default use $RUBY_VERSION"
  sudo -i -u ${USERNAME} bash -c "rvm rubygems current"
  sudo -i -u ${USERNAME} bash -c "gem install capistrano foreman pg pry awesome_print nokogiri oj multi_json faraday thin puma"
}


function setup_mininet () {
  # we install and then disable the openvswitch-controller so that it does not get turned in 
  # from later if installed as a dependency of mininets dependencies.
  sudo apt-get -y install openvswitch-controller
  sudo update-rc.d openvswitch-controller disable
  sudo apt-get -y install mininet
  sudo mn --test iperf
}


function main () {
  # setup_apt_cache
  
  # dist_upgrade
  setup_deploy_user
  install_common_tools
  build_tools
  
  # setup_postgres
  # setup_www
  # install_java
  # setup_monitoring
  # setup_rvm
  setup_mininet
}

main

