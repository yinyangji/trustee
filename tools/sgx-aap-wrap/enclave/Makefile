SGX_SDK ?= /home/chenpengyu/sgxsdk
SGX_MODE ?= HW
BUILD := build

ifeq ($(SGX_MODE), HW)
    TRTS := sgx_trts
    SERVICE := sgx_tservice
else
    TRTS := sgx_trts_sim
    SERVICE := sgx_tservice_sim
endif

CXX := g++
CC := gcc
EDGER := $(SGX_SDK)/bin/x64/sgx_edger8r
SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
LIB := $(SGX_SDK)/lib64

ENCLAVE_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(LIB) \
    -Wl,--whole-archive -l$(TRTS) -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_dcap_tvl -lsgx_tstdc -lsgx_tcxx -lsgx_pthread -lsgx_tcrypto -lsgx_tprotected_fs -l$(SERVICE) -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry \
    -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,--version-script=Enclave.lds

HOST_CFLAGS := -m64 -O2 -fPIC -std=c11 -I$(SGX_SDK)/include -I$(BUILD) -I.

.PHONY: all clean
all: $(BUILD)/libaap_fs_host.a $(BUILD)/libenclave.signed.so

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/Enclave_t.c $(BUILD)/Enclave_u.c: Enclave.edl | $(BUILD)
	cd $(BUILD) && $(EDGER) --trusted ../Enclave.edl --search-path $(SGX_SDK)/include --search-path $(SGX_SDK)/include/tlibc
	cd $(BUILD) && $(EDGER) --untrusted ../Enclave.edl --search-path $(SGX_SDK)/include --search-path $(SGX_SDK)/include/tlibc

$(BUILD)/Enclave_t.o: $(BUILD)/Enclave_t.c
	$(CC) -m64 -O2 -nostdinc -fpie -fstack-protector-strong -ffreestanding -fvisibility=hidden \
        -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -c $< -o $@

$(BUILD)/libenclave_sgxfs.a: sgxfs/src/lib.rs sgxfs/src/file.rs sgxfs/src/ffi.rs sgxfs/src/quote.rs sgxfs/Cargo.toml
	mkdir -p $(BUILD)
	cd sgxfs && env -i PATH="$$PATH" HOME="$$HOME" \
		RUSTUP_HOME="$${RUSTUP_HOME:-$$HOME/.rustup}" \
		CARGO_HOME="$${CARGO_HOME:-$$HOME/.cargo}" \
		cargo +stable build --release --offline --target-dir $(abspath $(BUILD))/rust
	cp $(BUILD)/rust/release/libenclave_sgxfs.a $@

$(BUILD)/libenclave.so: $(BUILD)/Enclave_t.o $(BUILD)/libenclave_sgxfs.a
	$(CXX) -m64 $(BUILD)/Enclave_t.o \
		-Wl,--whole-archive $(BUILD)/libenclave_sgxfs.a -Wl,--no-whole-archive \
		-o $@ $(ENCLAVE_LDFLAGS)

$(BUILD)/Enclave_private.pem:
	openssl genrsa -out $@ -3 3072

$(BUILD)/libenclave.signed.so: $(BUILD)/libenclave.so $(BUILD)/Enclave_private.pem Enclave.config.xml
	$(SIGNER) sign -key $(BUILD)/Enclave_private.pem -enclave $< -out $@ -config Enclave.config.xml

$(BUILD)/Enclave_u.o: $(BUILD)/Enclave_u.c
	$(CC) -m64 -O2 -fPIC -I$(SGX_SDK)/include -c $< -o $@

$(BUILD)/host.o: host.c $(BUILD)/Enclave_u.c
	$(CC) $(HOST_CFLAGS) -c host.c -o $@

$(BUILD)/libaap_fs_host.a: $(BUILD)/host.o $(BUILD)/Enclave_u.o
	ar rcs $@ $^

clean:
	rm -rf $(BUILD)
