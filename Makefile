TARGETS := aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu

X86_ENV := PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig

check:
	$(foreach t,$(TARGETS),$(if $(findstring x86_64,$(t)),$(X86_ENV)) cargo check --target $(t) &&) true

clippy:
	$(X86_ENV) cargo clippy --target x86_64-unknown-linux-gnu -- -D warnings

.PHONY: check clippy
