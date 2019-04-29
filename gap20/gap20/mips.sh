cd /disk/ytyu/Yocto/
source setup.sh meta-ked ked gap20

rm /disk/ytyu/cli/gap20/gap20
bitbake gap20 -c compile -f

#scp /disk/ytyu/cli/gap20/gap20 root@192.168.40.200:
#scp /disk/ytyu/cli/gap20/gap20 root@192.168.40.201:

