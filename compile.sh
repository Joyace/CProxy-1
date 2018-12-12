
function all {
    make clean
    make -j 2 OBJ=CProxy-64bit
    make CFLAGS='-static -O2' -j 2 OBJ=CProxy-64bit-static -j 2
    make clean
    PATH="/data/gcc/arm-linux-androideabi/bin:/data/gcc/bin:$PATH"
    make CFLAGS='-pie -O2' -j 2
    #make CFLAGS='-static -O2' -j 2 OBJ='CProxy-static'
}

cd "${0%/*}"
rm -f *.bak
all
rm -f *.o
