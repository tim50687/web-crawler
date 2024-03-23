move: complie
	mv ./target/release/project3-bgp-router ./crawler

complie: client
	~/.cargo/bin/cargo build -r

client: 
	curl https://sh.rustup.rs -sSf | sh -s -- -y \
	&& ~/.cargo/bin/rustup install --profile=minimal 1.75.0 \
	&& ~/.cargo/bin/rustup default 1.75.0 