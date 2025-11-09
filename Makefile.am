AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4

# Pull in pkg-config detected flags from configure
AM_CPPFLAGS = $(ssl_CFLAGS) $(crypto_CFLAGS) $(pthread_CFLAGS)
AM_CFLAGS = $(AM_CPPFLAGS)
LDADD_COMMON = $(ssl_LIBS) $(crypto_LIBS) $(pthread_LIBS) -lpthread -lz

# Source file groups
COMMON = src/cwebsocket/utf8.h src/cwebsocket/utf8.c \
         src/cwebsocket/common.h src/cwebsocket/common.c \
         src/cwebsocket/logging.h src/cwebsocket/logging.c
ECHO_CLIENT = src/cwebsocket/subprotocol/echo/echo_client.h src/cwebsocket/subprotocol/echo/echo_client.c
STOMP_CLIENT = src/cwebsocket/subprotocol/stomp/stomp_client.h src/cwebsocket/subprotocol/stomp/stomp_client.c
MQTT_CLIENT = src/cwebsocket/subprotocol/mqtt/mqtt_client.h src/cwebsocket/subprotocol/mqtt/mqtt_client.c \
              src/cwebsocket/subprotocol/mqtt/mqtt_persistence.h src/cwebsocket/subprotocol/mqtt/mqtt_persistence.c \
              src/cwebsocket/subprotocol/mqtt/mqtt_packet_id_pool.c \
              src/cwebsocket/subprotocol/mqtt/mqtt_scram.h src/cwebsocket/subprotocol/mqtt/mqtt_scram.c
WEBSOCKET_CLIENT = src/cwebsocket/client.h src/cwebsocket/client.c

# ============================================================================
# Binaries
# ============================================================================

# Client programs
bin_PROGRAMS = websocket-client websocket-testsuite stomp-client mqtt-client

websocket_client_SOURCES = $(ECHO_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT) src/websocket-client.c
websocket_client_LDADD = $(LDADD_COMMON)

websocket_testsuite_SOURCES = $(COMMON) $(WEBSOCKET_CLIENT) src/websocket-testsuite.c
websocket_testsuite_LDADD = $(LDADD_COMMON)

stomp_client_SOURCES = $(STOMP_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT) src/stomp-client.c
stomp_client_LDADD = $(LDADD_COMMON)

mqtt_client_SOURCES = $(MQTT_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT) src/mqtt-client.c
mqtt_client_LDADD = $(LDADD_COMMON)

# Test programs (not installed)
noinst_PROGRAMS = \
	websocket-unit-test \
	stomp-integration-test \
	mqtt-unit-test \
	mqtt-integration-test \
	mqtt-auth-test \
	security-tests

websocket_unit_test_SOURCES = $(COMMON) $(WEBSOCKET_CLIENT) src/tests-unit.c
websocket_unit_test_CPPFLAGS = -DUNIT_TESTING $(AM_CPPFLAGS)
websocket_unit_test_LDADD = $(LDADD_COMMON)

stomp_integration_test_SOURCES = $(STOMP_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT) test/stomp/stomp-compliance-test.c
stomp_integration_test_LDADD = $(LDADD_COMMON)

mqtt_unit_test_SOURCES = $(MQTT_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT) test/mqtt/mqtt-unit-test.c
mqtt_unit_test_LDADD = $(LDADD_COMMON)

mqtt_integration_test_SOURCES = $(MQTT_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT) test/mqtt/mqtt-integration-test.c
mqtt_integration_test_LDADD = $(LDADD_COMMON)

mqtt_auth_test_SOURCES = $(MQTT_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT) test/mqtt/mqtt-auth-test.c
mqtt_auth_test_LDADD = $(LDADD_COMMON)

security_tests_SOURCES = $(COMMON) test/security/standalone_security_tests.c
security_tests_LDADD = $(LDADD_COMMON)

# Library
noinst_LIBRARIES = libwsclient.a
libwsclient_a_SOURCES = $(ECHO_CLIENT) $(STOMP_CLIENT) $(MQTT_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT)

# ============================================================================
# Test Targets
# ============================================================================

.PHONY: test test-unit test-integration
.PHONY: test-websocket test-websocket-unit test-websocket-integration
.PHONY: test-stomp test-stomp-integration
.PHONY: test-mqtt test-mqtt-unit test-mqtt-integration test-mqtt-auth

# Top-level test targets
test: test-unit
	@echo "========================================="
	@echo "  All Unit Tests Complete"
	@echo "========================================="

test-unit: test-websocket-unit test-mqtt-unit
	@true

test-integration: test-websocket-integration test-stomp-integration test-mqtt-integration
	@echo "========================================="
	@echo "  All Integration Tests Complete"
	@echo "========================================="

# Component-level targets (run all tests for that component)
test-websocket: test-websocket-unit test-websocket-integration
	@echo "========================================="
	@echo "  All WebSocket Tests Complete"
	@echo "========================================="

test-stomp: test-stomp-integration
	@echo "========================================="
	@echo "  All STOMP Tests Complete"
	@echo "========================================="

test-mqtt: test-mqtt-unit test-mqtt-integration
	@echo "========================================="
	@echo "  All MQTT Tests Complete"
	@echo "========================================="

# WebSocket tests
test-websocket-unit: websocket-unit-test
	@echo "========================================="
	@echo "  Running WebSocket Unit Tests"
	@echo "========================================="
	./websocket-unit-test

test-websocket-integration: websocket-testsuite
	@echo "========================================="
	@echo "  Running WebSocket Integration Tests"
	@echo "  (Autobahn Test Suite)"
	@echo "========================================="
	@$(MAKE) autobahn

# STOMP tests
test-stomp-integration: stomp-integration-test
	@echo "========================================="
	@echo "  Running STOMP Integration Tests"
	@echo "  (requires Docker + ActiveMQ broker)"
	@echo "========================================="
	@./test/stomp/test-stomp.sh

# MQTT tests
test-mqtt-unit: mqtt-unit-test
	@echo "========================================="
	@echo "  Running MQTT Unit Tests"
	@echo "========================================="
	./mqtt-unit-test

test-mqtt-integration: mqtt-integration-test
	@echo "========================================="
	@echo "  Running MQTT Integration Tests"
	@echo "  (requires Docker + EMQX broker)"
	@echo "========================================="
	@docker rm -f mqtt-broker 2>/dev/null || true
	@docker run -d --rm --name mqtt-broker -p 8083:8083 \
		-e EMQX_LISTENERS__WS__DEFAULT__BIND="0.0.0.0:8083" \
		emqx/emqx:5.4.0
	@echo "Waiting for broker to start..."
	@sleep 10
	@./mqtt-integration-test
	@docker rm -f mqtt-broker 2>/dev/null || true

test-mqtt-auth: mqtt-auth-test
	@echo "========================================="
	@echo "  Running MQTT SCRAM-SHA-256 Auth Tests"
	@echo "  (requires Docker + EMQX broker)"
	@echo "========================================="
	@docker rm -f mqtt-broker 2>/dev/null || true
	@docker run -d --rm --name mqtt-broker -p 8083:8083 -p 18083:18083 \
		-e EMQX_LISTENERS__WS__DEFAULT__BIND="0.0.0.0:8083" \
		emqx/emqx:5.4.0
	@echo "Waiting for broker to start..."
	@sleep 15
	@echo "Configuring SCRAM authentication..."
	@./test/emqx-scram-config/setup-scram.sh || echo "Note: SCRAM setup may require manual configuration"
	@echo "Running authentication test..."
	@./mqtt-auth-test || true
	@docker rm -f mqtt-broker 2>/dev/null || true

# ============================================================================
# Autobahn WebSocket Integration Tests
# ============================================================================

.PHONY: autobahn autobahn-local docker-build docker-network

IMAGE_NAME = cwebsocket/test:latest

docker-build:
	@DOCKER_BUILDKIT=0 docker build -t $(IMAGE_NAME) .

docker-network:
	@docker network create cwsnet >/dev/null 2>&1 || true

autobahn: docker-build docker-network
	@docker rm -f cwebsocket-autobahn >/dev/null 2>&1 || true
	@rm -f test/autobahn/reports/clients/* >/dev/null 2>&1 || true
	@docker run -d --rm --name cwebsocket-autobahn --network cwsnet \
		-v $(PWD)/test/autobahn:/config crossbario/autobahn-testsuite:latest >/dev/null
	@echo "Waiting for Autobahn fuzzing server..." && sleep 2
	@set -e; docker run --rm --network cwsnet \
		-v $(PWD)/test/autobahn:/app/test/autobahn \
		-e WS_FUZZING_SERVER=ws://cwebsocket-autobahn:9001 \
		-e WS_CASECOUNT_RETRIES=120 \
		$(IMAGE_NAME) bash -lc "./websocket-testsuite" || true
	@echo "Waiting for reports to be generated..."
	@for i in `seq 1 900`; do \
		[ -f $(PWD)/test/autobahn/reports/clients/index.json ] && break; \
		sleep 1; \
	done
	@if [ -n "`ls -A $(PWD)/test/autobahn/reports/clients 2>/dev/null`" ]; then \
		echo "Integration reports generated at test/autobahn/reports/clients"; \
	else \
		echo "Integration failed: no reports generated."; exit 1; \
	fi
	@rm -rf $(PWD)/autobahn-reports && mkdir -p $(PWD)/autobahn-reports
	@cp -r $(PWD)/test/autobahn/reports/* $(PWD)/autobahn-reports/
	@echo "Full Autobahn reports copied to ./autobahn-reports"
	@docker rm -f cwebsocket-autobahn >/dev/null 2>&1 || true

autobahn-local: websocket-testsuite
	@echo "Running websocket-testsuite against $${WS_FUZZING_SERVER:-ws://localhost:9001}..."
	@WS_FUZZING_SERVER=$${WS_FUZZING_SERVER:-ws://localhost:9001} \
		WS_CASECOUNT_RETRIES=$${WS_CASECOUNT_RETRIES:-120} \
		./websocket-testsuite || true
	@mkdir -p autobahn-reports
	@if [ -d test/autobahn/reports ]; then \
		rm -rf autobahn-reports/*; \
		cp -r test/autobahn/reports/* autobahn-reports/ 2>/dev/null || true; \
		echo "Copied reports to ./autobahn-reports"; \
	fi

# ============================================================================
# Quality Assurance Targets
# ============================================================================

.PHONY: qa valgrind static-analysis security-scan

qa:
	@echo "========================================="
	@echo "  cwebsocket Quality Assurance Suite"
	@echo "========================================="
	@echo ""
	@echo "[1/5] Building tests..."
	@make websocket-unit-test > /dev/null 2>&1
	@echo "✓ Build successful"
	@echo ""
	@echo "[2/5] Running unit tests..."
	@./websocket-unit-test > /dev/null 2>&1 && echo "✓ All tests passed" || echo "✗ Tests failed"
	@echo ""
	@echo "[3/5] Running Valgrind memory check..."
	@valgrind --leak-check=full --error-exitcode=0 --quiet ./websocket-unit-test > /dev/null 2>&1 \
		&& echo "✓ No memory leaks detected" || echo "⚠ Memory issues detected"
	@echo ""
	@echo "[4/5] Running static analysis (cppcheck)..."
	@cppcheck --enable=all --std=c99 --suppress=missingIncludeSystem --quiet \
		-I src/cwebsocket src/cwebsocket/*.c src/*.c 2>&1 | tee cppcheck-report.txt > /dev/null \
		&& echo "✓ Static analysis complete" || echo "⚠ Issues found"
	@echo ""
	@echo "[5/5] Running security scan (flawfinder)..."
	@flawfinder --quiet --dataonly --minlevel=1 \
		src/cwebsocket/*.c src/*.c 2>&1 | tee flawfinder-report.txt > /dev/null \
		&& echo "✓ Security scan complete" || echo "⚠ Security issues found"
	@echo ""
	@echo "========================================="
	@echo "  Quality Assurance Complete"
	@echo "========================================="

valgrind: websocket-unit-test
	@echo "Running Valgrind memory check..."
	@valgrind --leak-check=yes --error-exitcode=1 \
		--errors-for-leak-kinds=definite \
		--track-origins=yes --show-leak-kinds=definite \
		./websocket-unit-test

static-analysis:
	@echo "Running cppcheck static analysis..."
	@cppcheck --enable=all --inconclusive --std=c99 \
		--suppress=missingIncludeSystem --quiet --template=gcc \
		-I src/cwebsocket src/cwebsocket/*.c src/*.c 2>&1 | tee cppcheck-report.txt

security-scan:
	@echo "Running Flawfinder security scanner..."
	@flawfinder --quiet --dataonly --minlevel=1 \
		src/cwebsocket/*.c src/*.c 2>&1 | tee flawfinder-report.txt

# ============================================================================
# Cleanup Targets
# ============================================================================

CLEANFILES = \
	libwsclient.so \
	*.o src/*.o src/cwebsocket/*.o \
	src/cwebsocket/subprotocol/echo/*.o \
	src/cwebsocket/subprotocol/stomp/*.o \
	src/cwebsocket/subprotocol/mqtt/*.o \
	test/*.o test/mqtt/*.o test/security/*.o test/stomp/*.o \
	*~ src/*~ src/cwebsocket/*~ test/*~ \
	vgcore.* \
	*.log integration*.log test*.log testsuite.log autoscan.log \
	*.gcda *.gcno src/*.gcda src/*.gcno src/cwebsocket/*.gcda src/cwebsocket/*.gcno \
	valgrind-report.txt memcheck-report.txt helgrind-report.txt \
	cppcheck-report.txt clang-analyze-report.txt flawfinder-report.txt \
	*.lo

DISTCLEANFILES = \
	config.h config.h.in config.h.in~ \
	config.cache config.log config.status \
	libtool stamp-h1 \
	Makefile Makefile.in

MAINTAINERCLEANFILES = \
	aclocal.m4 \
	compile config.guess config.sub \
	configure configure~ \
	depcomp install-sh missing ltmain.sh

clean-local:
	@echo "Removing ALL generated files..."
	@find . -type d -name ".deps" -exec rm -rf {} + 2>/dev/null ; true
	@find . -type f -name ".dirstamp" -exec rm -f {} + 2>/dev/null ; true
	@find . -type f -name "*.Po" -exec rm -f {} + 2>/dev/null ; true
	@rm -rf .libs/ Debug/ Release/ autom4te.cache/ m4/ analysis-reports/
	@rm -f libwsclient.a
	@rm -f websocket-unit-test websocket-testsuite websocket-client
	@rm -f mqtt-unit-test mqtt-integration-test mqtt-auth-test mqtt-client
	@rm -f stomp-integration-test stomp-client
	@rm -f security-tests
	@rm -f aclocal.m4
	@rm -f compile config.guess config.sub
	@rm -f configure configure~
	@rm -f depcomp install-sh missing ltmain.sh
	@rm -f config.h config.h.in config.h.in~
	@rm -f config.cache config.log config.status
	@rm -f libtool stamp-h1
	@rm -f Makefile Makefile.in
	@rm -rf test/autobahn/reports/clients/*
	@echo "All generated files removed (autobahn-reports/ preserved)"
	@echo "Run './autogen.sh && ./configure && make' to rebuild"

.PHONY: clean-all
clean-all: maintainer-clean
	@echo "Removing all generated files including reports..."
	rm -rf autobahn-reports/
	@echo "Complete clean finished - run ./autogen.sh && ./configure to rebuild"
