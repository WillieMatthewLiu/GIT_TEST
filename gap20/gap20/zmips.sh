make clean
cd /disk/zqzhang/Yocto1.2/
source setup.sh meta-ked ked build_gap20
bitbake gap20 -c compile -f




