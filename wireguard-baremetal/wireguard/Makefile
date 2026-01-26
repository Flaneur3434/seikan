# WireGuard Ada/SPARK - Test Harness Commands
#
# Usage:
#   make test-gen-crypto    Generate crypto test harness
#   make test-run-crypto    Build and run crypto tests
#   make test-crypto        Generate + run crypto tests
#   make clean-all          Clean all build artifacts

PLATFORM ?= host
CRYPTO_BACKEND ?= libsodium

TEST_ROOT := ../tests/ada
IGNORE_FILE := $(TEST_ROOT)/gnattest.ignore

# Common gnattest flags
GNATTEST_FLAGS := -XPLATFORM=$(PLATFORM) -XCRYPTO_BACKEND=$(CRYPTO_BACKEND)

# Crypto tests
CRYPTO_HARNESS := $(TEST_ROOT)/crypto/harness
CRYPTO_TESTS := $(TEST_ROOT)/crypto/tests

.PHONY: test-gen-crypto test-build-crypto test-run-crypto test-crypto

test-gen-crypto:
	gnattest -P crypto.gpr $(GNATTEST_FLAGS) \
		--harness-dir=$(CRYPTO_HARNESS) \
		--tests-dir=$(CRYPTO_TESTS) \
		--ignore=$(IGNORE_FILE)

test-build-crypto:
	gprbuild -P $(CRYPTO_HARNESS)/test_driver.gpr $(GNATTEST_FLAGS)

test-run-crypto: test-build-crypto
	$(CRYPTO_HARNESS)/test_runner

test-crypto: test-gen-crypto test-run-crypto

# Utils tests
UTILS_HARNESS := $(TEST_ROOT)/utils/harness
UTILS_TESTS := $(TEST_ROOT)/utils/tests

.PHONY: test-gen-utils test-build-utils test-run-utils test-utils

test-gen-utils:
	gnattest -P utils.gpr $(GNATTEST_FLAGS) \
		--harness-dir=$(UTILS_HARNESS) \
		--tests-dir=$(UTILS_TESTS) \
		--ignore=$(IGNORE_FILE)

test-build-utils:
	gprbuild -P $(UTILS_HARNESS)/test_driver.gpr $(GNATTEST_FLAGS)

test-run-utils: test-build-utils
	$(UTILS_HARNESS)/test_runner

test-utils: test-gen-utils test-run-utils

# All tests
.PHONY: test-gen-all test-all

test-gen-all: test-gen-utils test-gen-crypto

test-all: test-utils test-crypto

# Clean
.PHONY: clean-tests clean-all

clean-tests:
	rm -rf $(CRYPTO_HARNESS)/obj $(CRYPTO_HARNESS)/test_runner
	rm -rf $(UTILS_HARNESS)/obj $(UTILS_HARNESS)/test_runner

clean-all: clean-tests
	rm -rf obj lib
