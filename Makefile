SHELL := /bin/sh
PYTHON ?= python3
GO ?= go
RUN = $(PYTHON) scripts/run.py
.PHONY: bootstrap build fmt fmt-check lint static test-unit test-integration test-acceptance race fuzz mutation security security-online benchmark benchmark-smoke demo inspect verify clean-verify containment public-audit
bootstrap:
	sh scripts/bootstrap.sh
build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/relayfence ./cmd/relayfence
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/relaybench ./cmd/relaybench
fmt:
	gofmt -w cmd internal
fmt-check:
	sh scripts/fmt_check.sh
lint: fmt-check static
static:
	$(RUN) --category static -- $(GO) vet ./...
test-unit:
	$(RUN) --category unit -- $(GO) test -count=1 -timeout=60s -run '^(TestAuthority|TestAuthorityRejectsUnicode|TestOversizedPolicyRejectedBeforePersistence|TestPublicAddress|TestMixedDNS|TestStrictJSON|TestPolicyValidation|TestAdmissionLimits|TestAdmissionConcurrent|TestBudgetConcurrent|TestRevisionFence|TestPolicyCASConcurrent|TestAuditIntegrity|TestInspectEscapes)$$' ./internal/relayfence
test-integration:
	$(RUN) --category integration -- $(GO) test -count=1 -timeout=60s ./cmd/relayfence
	$(RUN) --category integration -- $(GO) test -count=1 -timeout=60s -run '^(TestAcceptanceMTLS|TestAuthorizeBeforeDNS|TestDNSPinning|TestReviewDNSPinningRealTCP|TestReviewMixedDNSNoUpstream|TestReviewMTLSNoUpstream|TestReviewAuditFailureJoinedPayload|TestRevokePending|TestRevokeActive|TestPolicyPersistence|TestPolicyPersistenceSizeBound|TestTimeouts|TestHalfClose|TestAuditFailure|TestRelayBudget|TestBufferedPayload|TestShutdown|TestAdmin|TestDemo|TestRelayShortWrites|TestRelayBidirectionalBudget|TestExpiredMTLS|TestConnectRequestTargetAuthority|TestTLSCloseStalledReader|TestGatewayTLSCloseStalledReader|TestGatewayTLSCloseBlockedApplicationWrite|TestReviewBenchmarkWarmupFailureRetained|TestReviewBenchmarkRevocationFailureRetained|TestReviewBenchmarkReportWriteFailurePropagates|TestReviewBenchmarkSuccessReport)$$' ./internal/relayfence
test-acceptance:
	$(RUN) --category acceptance -- $(GO) test -json -count=1 -timeout=60s ./...
race:
	$(RUN) --category race --timeout 180 -- $(GO) test -race -count=3 -timeout=120s ./...
fuzz:
	$(RUN) --category fuzz --timeout 60 -- $(GO) test -run '^$$' -fuzz '^FuzzAuthority$$' -fuzztime=5s -parallel=2 ./internal/relayfence
	$(RUN) --category fuzz --timeout 60 -- $(GO) test -run '^$$' -fuzz '^FuzzStrictJSON$$' -fuzztime=5s -parallel=2 ./internal/relayfence
mutation:
	$(RUN) --category mutation --timeout 180 -- $(PYTHON) scripts/mutate.py
security: public-audit
	$(RUN) --category security -- $(GO) test -count=1 -run '^(TestPublicAddress|TestMixedDNS|TestStrictJSON|TestAcceptanceMTLS|TestExpiredMTLS|TestAuditFailure|TestInspectEscapes)$$' ./internal/relayfence
security-online:
	$(RUN) --category security-online --timeout 180 -- $(PYTHON) scripts/security_online.py
benchmark:
	$(RUN) --category benchmark-micro --timeout 90 -- $(GO) test -run '^$$' -bench '^(BenchmarkAuthority|BenchmarkPublicAddress|BenchmarkAdmission|BenchmarkBudget)$$' -benchmem -count=5 ./internal/relayfence
	$(RUN) --category benchmark --timeout 240 -- $(PYTHON) scripts/benchmark.py
benchmark-smoke:
	$(RUN) --category benchmark-smoke --timeout 120 -- $(PYTHON) scripts/benchmark.py --smoke
demo: build
	$(RUN) --category demo -- $(PYTHON) scripts/demo.py
inspect:
	$(PYTHON) scripts/demo.py --latest
verify: bootstrap build fmt-check static test-unit test-integration test-acceptance race security
clean-verify:
	$(RUN) --category clean-environment --timeout 240 -- sh scripts/clean_verify.sh
containment:
	$(RUN) --category containment --timeout 180 -- sh scripts/containment.sh
public-audit:
	$(RUN) --category public-scope -- $(PYTHON) scripts/check_public_tree.py
