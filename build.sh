./configure \
          --prefix=/usr \
          --mandir=/usr/share/man \
          --sysconfdir=/etc \
          --localstatedir=/var \
          --libexecdir=/usr/lib \
          --with-dbusconfdir=/usr/share \
          --enable-btpclient \
          --enable-midi \
          --enable-sixaxis \
          --enable-hid2hci \
          --enable-mesh \
          --enable-experimental \
          --enable-library \
          --enable-deprecated # to enable deprectated tools

make
