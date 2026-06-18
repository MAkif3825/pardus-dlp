build:
	make -C src

clean:
	make -C src clean

install:
	sudo apt update
	sudo apt-get install -y --no-install-recommends \
        libbpf-dev libelf1 libelf-dev zlib1g-dev \
        make clang llvm pkg-config
