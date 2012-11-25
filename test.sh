#!/bin/bash -x -e

vagrant up
vagrant ssh 'sudo mn --test pingpair'
vagrant ssh 'sudo mn --test ipef'