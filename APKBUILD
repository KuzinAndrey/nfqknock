pkgname="nfqknock"
pkgver="0.0.1"
pkgrel="1"
maintainer="Kuzin Andrey <kuzinandrey@yandex.ru>"
pkgdesc="Knock daemon based on NFQUEUE"
url="https://github.com/KuzinAndrey/nfqknock"
license="MIT"
depends="musl libnfnetlink libnetfilter_queue openssl"
depends_dev="gcc make musl-dev libnfnetlink-dev libnetfilter_queue-dev openssl-dev"
builddepends="${depends_dev}"
arch="all"

build() {
    make
}

package() {
    make DESTDIR="$pkgdir" install
}
