# mininet dev box

This Vagrant file use a fresh install of ubuntu 12.10 64 bit server edition.  
Get started by installing Vithe dependencies and bringing up the development vm.

    bundle install
    
    vagrant up 
  
will bring up a VM, and run the setup.sh script, which will setuo wireshark and mininet on the vm.
You can login and try a few mininet commands.

    vagrant ssh
    root@quetzal64:~# mn --test iperf
    *** Creating network
    *** Adding controller
    *** Adding hosts:
    h1 h2 
    *** Adding switches:
    s1 
    *** Adding links:
    (h1, s1) (h2, s1) 
    *** Configuring hosts
    h1 h2 
    *** Starting controller
    *** Starting 1 switches
    s1 
    *** Iperf: testing TCP bandwidth between h1 and h2
    *** Results: ['118 Mbits/sec', '119 Mbits/sec']
    *** Stopping 2 hosts
    h1 h2 
    *** Stopping 1 switches
    s1 ...
    *** Stopping 1 controllers
    c0 
    *** Done
    completed in 5.415 seconds
  
  
Login to the interactive session to explore
    
    root@quetzal64:~# mn
    *** Creating network
    *** Adding controller
    *** Adding hosts:
    h1 h2 
    *** Adding switches:
    s1 
    *** Adding links:
    (h1, s1) (h2, s1) 
    *** Configuring hosts
    h1 h2 
    *** Starting controller
    *** Starting 1 switches
    s1 
    *** Starting CLI:
    mininet> help

    Documented commands (type help <topic>):
    ========================================
    EOF    exit   intfs     link   noecho    py    source
    dpctl  gterm  iperf     net    pingall   quit  time  
    dump   help   iperfudp  nodes  pingpair  sh    xterm 

    You may also send a command to a node using:
      <node> command {args}
    For example:
      mininet> h1 ifconfig

    The interpreter automatically substitutes IP addresses
    for node names when a node is the first arg, so commands
    like
      mininet> h2 ping h3
    should work.
    

### Default Users 

There are 2 default users setup with passwordless usdo and username/password of:
 
  - vagrant/vagrant
    - The vagrant user also has a .ssh/authorized_keys file matching the commonly used vagrant insecrure_private_key.
  - openflow/openflow

### Netoworking

- eth0: The first interface configured in virtualbox is the default NAT interface using the intel driver.

- eth1: configured to be on hostonly network vboxnet0 with ip address of 192.168.33.2 and virt-io driver. 
  
  
###  Build the Basebox from scratch

The creation of this basebox was automated with the vewee tool.  Details of the build configuration are in the definitions/ directory, and can be used
to recreate the basebox from iso.

    vagrant basebox build 'quetzal64'
    vagrant basebox validate 'quetzal64'
    vagrant basebox export 'quetzal64'
    vagrant box add quetzal64
    vagrant up
    vagrant ssh
