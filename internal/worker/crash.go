package worker

// Named crash-injection points. Tests and the daemon use these constants so
// point names do not drift between the production code and the test harness.
const (
	CrashPointInputCommit              = "input-commit"
	CrashPointOutputFsync              = "output-fsync"
	CrashPointReceiptSigned            = "receipt-signed"
	CrashPointReceiptCommitted         = "receipt-committed"
	CrashPointBuilderSaveOutputPackage = "builder-save-output-package"
	CrashPointOutputAvailableHeld      = "output-available-held"
	CrashPointOutputAvailableReleased  = "output-available-released"
)
